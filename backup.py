#!/usr/bin/env python

import argparse
import glob
import gzip
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
from contextlib import contextmanager
from typing import Callable

import arrow
import requests

import deepy.cfg
import deepy.config.events
import deepy.config_sync
import deepy.defender
import deepy.defender.dfdb
import deepy.defender.policies as policies
import deepy.dimensions.ddb
from deepy.dimensions.exceptions import ConfigdUnreachable
import deepy.limits
import deepy.log
from deepy.router import config_bgp
import deepy.salty
import deepy.sql_helper
import deepy.stats
import deepy.ui.database
from deepy.config.defender import emit_policy_update
from deepy.defender.mitigation_devices.radware import RadwareDevice
from deepy.defender.models import Policy
from deepy.encryption_utils import EncryptFile
from deepy.network_firewall.cleanup import force_cleanup_dnf
from deepy.store.errors import StoreHDFSRefuseZeroLength

LOCAL_SLICE_FIELDS = [
    "build_updates",
    "credentials",
    "customer_id",
    "deployment",
    "iptables",
    "snmp_server_configs",
    "vms",
]
METRIC_BASE = "config_sync"

DBS_TO_DUMP = ["deepui", "defender"]

CONFIG_DIR_FILES_TO_IGNORE = [
    ".git",
    "auth.json",
    "deployment.json",
    "redis.json",
    "license.json",
    "impala_dimensions_cache.json.gz",
    "impala_row_count_cache.json.gz",
    "cube_file_size_cache.json.gz",
    "config_sync.json",
]

DIMENSIONS_DIR_FILES_TO_IGNORE = ["dcu.json.gz"]

DB_TABLE_EXCLUSIONS = {
    "defender": [
        {"table_name": "HealthStatusTopic", "regex_override": ""},
        {"table_name": "HealthStatusProduct", "regex_override": ""},
        {"table_name": "HealthStatusProductTopicLink", "regex_override": ""},
        {"table_name": "HealthStatusDeviceTopic", "regex_override": ""},
        {"table_name": "subscriber_info", "regex_override": ""},
        {"table_name": "subscriber_match", "regex_override": ""},
        {"table_name": "subscriber_optin_by_addr", "regex_override": ""},
        {"table_name": "subscriber_optin_by_subscr", "regex_override": ""},
        {"table_name": "VIP", "regex_override": ""},
    ]
}

DeploymentType = deepy.config_sync.DeploymentType
ConfigSyncMode = deepy.config_sync.ConfigSyncMode


def parse_args():
    p = argparse.ArgumentParser(
        description="""
    Dumps and loads configuration between a primary and secondary deployment for
    the purpose of having a backup cluster for high availability.
        """
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="enable verbose logging",
    )
    action = p.add_mutually_exclusive_group(required=True)
    action.add_argument(
        "-c",
        "--config",
        dest="show_config",
        action="store_true",
        default=False,
        help="print config sync configs",
    )
    action.add_argument(
        "-d",
        "--dump",
        dest="dump_config",
        action="store_true",
        default=False,
        help="dump configs and store in nginx location",
    )
    action.add_argument(
        "-g",
        "--get",
        dest="get_config",
        action="store_true",
        default=False,
        help="download configs and store in hdfs",
    )
    action.add_argument(
        "-l",
        "--load",
        dest="load_config",
        action="store_true",
        default=False,
        help="load configs from hdfs",
    )
    action.add_argument(
        "-s",
        "--sync",
        dest="sync_config",
        action="store_true",
        default=False,
        help="download configs to hdfs and then load them",
    )
    action.add_argument(
        "-p",
        "--prune",
        dest="prune_config",
        action="store_true",
        default=False,
        help="prune config dumps",
    )
    action.add_argument(
        "--make-active",
        dest="make_active",
        action="store_true",
        default=False,
        help="make this deployment active for config sync, restarts all services",
    )
    action.add_argument(
        "--make-passive",
        dest="make_passive",
        action="store_true",
        default=False,
        help="make this deployment passive for config sync, restarts all services",
    )
    action.add_argument(
        "--make-upgrade",
        dest="make_upgrade",
        action="store_true",
        default=False,
        help="puts deployment in config sync upgrade mode, restarts all services",
    )
    action.add_argument(
        "--make-primary",
        dest="make_primary",
        action="store_true",
        default=False,
        help="make this deployment primary for config sync, restarts all services",
    )
    action.add_argument(
        "--make-secondary",
        dest="make_secondary",
        action="store_true",
        default=False,
        help="make this deployment secondary for config sync, restarts all services",
    )
    p.add_argument("--hostname")
    p.add_argument("--api-key")
    action.add_argument(
        "--cron",
        dest="cron",
        action="store_true",
        default=False,
        help="change the cron schedule for this deployment",
    )
    p.add_argument("--job")
    p.add_argument("--schedule")
    action.add_argument(
        "--failover",
        dest="failover",
        action="store_true",
        default=False,
        help="Detect and transition the failover state for this deployment",
    )

    args = p.parse_args()
    if args.cron and (args.job is None or args.schedule is None):
        p.error("--cron requires both --job and --schedule")
    return args


def prune_config():
    """Prune all but n most recent config dumps where n = num_dumps_to_keep or 10"""
    num_to_keep = deepy.cfg.sync_config.get("num_dumps_to_keep", 10)
    all_config_files = deepy.cfg.store.ls_files_remote_recursive_by_type(
        deepy.cfg.sync_dir, desired_file_type=(".enc", ".gz"), dir_mtimes=True
    )
    if len(all_config_files) <= num_to_keep:
        deepy.log.debug("Not enough config dump files to prune")
        return
    deepy.log.info(f"Pruning all but {num_to_keep} most recent config dumps")

    # sort files in order from least to most recent
    def get_mtime(fileinfo):
        return arrow.get(fileinfo[1])

    all_config_files.sort(key=get_mtime, reverse=True)

    # prune all but n most recent files
    files_to_prune = [path for path, _ in all_config_files[num_to_keep:]]
    deepy.cfg.store.rm_files(files_to_prune)


def show_config():
    """Print json-formatted sync configuration to stdout."""
    # IDEA show both global config sync config and manifest.json
    print(json.dumps(deepy.cfg.sync_config, indent=4))


def emit_stats(func):
    def wrap(*args, **kwargs):
        stats = deepy.stats.DeepStats(prefix=f"{METRIC_BASE}.{func.__name__}")
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            stats.event("success")
            stats.gauge("run_time", time.time() - start_time)
            return result
        except:
            stats.event("failure")
            raise

    return wrap


def _tables_to_exclude_from_db_dump(db_name: str):
    """Loop through tables configured for exclusion in a given database to build the
    -T pattern OR --exclude-table=pattern
    args to pg_dump. For example, tables "HealthStatusTopic" + "HealthStatusTopic", will return
    ['--exclude-table=public."HealthStatusTopic"*' ,'--exclude-table=public."HealthStatusProduct"*']
    where the quotes are needed specify an upper-case or mixed-case name
    """
    exclude_table_cli_args = []
    schema_name = "public"
    for db_table in DB_TABLE_EXCLUSIONS.get(db_name, []):
        table_name = db_table["table_name"]
        pattern = db_table["regex_override"] or f'{schema_name}."{table_name}"*'
        exclude_table_cli_args.append(f"--exclude-table={pattern}")

    return exclude_table_cli_args


def _dump_postgres(output_dir):
    """Dump defender and deepui dbs to the given output_dir."""
    host_name = deepy.sql_helper.get_sql_host()
    for db in DBS_TO_DUMP:
        output_file = os.path.join(output_dir, f"{db}.sql")
        with open(output_file, "w") as dumphandle:
            db_name = f"{db}_{deepy.cfg.deployment_id}"
            pg_dump_cmd = [
                "pg_dump",
                # Use custom format so that we can use pg_restore
                "-Fc",
                f"--dbname=postgresql://{deepy.cfg.database_username}:"
                f"{deepy.cfg.database_password}@{host_name}/{db_name}",
            ]
            pg_dump_cmd.extend(_tables_to_exclude_from_db_dump(db))

            result = subprocess.run(
                pg_dump_cmd,
                stdout=dumphandle,
            )
            if result.returncode != 0:
                log_fatal(
                    f"failed to dump postgres db {db_name} to {output_file} . Cmd args: {result.args}"
                )


def doesnt_end_with(patterns):
    def ignore_filter(path, names):
        return [
            name
            for name in names
            if name == ".git"
            or (
                os.path.isfile(os.path.join(path, name))
                and not any(name.endswith(pattern) for pattern in patterns)
            )
        ]

    return ignore_filter


def _dump_local_config(staging_dir):
    shutil.copytree(
        deepy.cfg.context_dir,
        os.path.join(staging_dir, "context"),
        ignore=shutil.ignore_patterns(".git"),
    )
    shutil.copytree(
        deepy.cfg.cache_config_dir,
        os.path.join(staging_dir, "config"),
        ignore=shutil.ignore_patterns(*CONFIG_DIR_FILES_TO_IGNORE),
    )
    shutil.copytree(
        deepy.cfg.dimensions_dir,
        os.path.join(staging_dir, "dimensions"),
        ignore=doesnt_end_with([".json.gz", ".json"]),
    )
    shutil.copytree(
        deepy.cfg.sql_dimensions_dir,
        os.path.join(staging_dir, "sql_dimensions"),
        ignore=doesnt_end_with([".json.gz", ".json"]),
    )
    shutil.copyfile(
        os.path.join(deepy.cfg.cache_dir, "dimension_mappings.json.gz"),
        os.path.join(staging_dir, "dimension_mappings.json.gz"),
    )


@contextmanager
def staging_area(relative_path):
    staging_dir = os.path.join(deepy.cfg.pathman.data_tmp, relative_path)
    try:
        yield staging_dir
    finally:
        if os.path.exists(staging_dir):
            shutil.rmtree(staging_dir)


def _package_tarfile(output_file, staging_dir):
    with tempfile.TemporaryDirectory(dir=deepy.cfg.data_tmp) as temp_dir_path:
        actual_archive_destination_path = os.path.join(temp_dir_path, output_file)
        with deepy.cfg.store.write_file_atomically(
            actual_archive_destination_path
        ) as tmp_path:
            with tarfile.open(tmp_path, "w:gz") as tar:
                # Use arcname to remove the toplevel dir
                tar.add(staging_dir, arcname="")

        encrypted_archive_destination_path = os.path.join(
            deepy.cfg.pathman.sync_dir, output_file + ".enc"
        )
        _encrypt_file(
            actual_archive_destination_path, encrypted_archive_destination_path
        )


def _encrypt_file(input_file, output_file):
    with deepy.cfg.store.write_file_atomically(output_file) as out_file:
        try:
            encryption_key = deepy.cfg.sync_config.get(
                "deployment_encryption_key",
                deepy.config_sync.CONFIG_SYNC_ENCRYPTION_KEY,
            ).encode("utf8")
            file_encryption_obj = EncryptFile(encryption_key, input_file, out_file)
            file_encryption_obj.encrypt()
        except:
            log_fatal(f"Error encrypting config_sync file: {input_file}")


def _decrypt_file(input_file, output_file):
    with deepy.cfg.store.write_file_atomically(output_file) as out_file:
        try:
            encryption_key = deepy.cfg.sync_config.get(
                "deployment_encryption_key",
                deepy.config_sync.CONFIG_SYNC_ENCRYPTION_KEY,
            ).encode("utf8")
            file_encryption_obj = EncryptFile(encryption_key, input_file, out_file)
            file_encryption_obj.decrypt()
        except:
            log_fatal(f" Error decrypting config_sync file: {input_file} ")


def _get_current_version():
    build_updates = deepy.cfg.slice_config.get("build_updates", {})
    current_version = build_updates.get("handpatch", build_updates.get("revision"))
    if not current_version:
        log_fatal("_get_current_version: unable to get current pipedream version")
    return current_version


@emit_stats
def dump_config():
    """
    Dumps config from the local /pipedream/cache directory and postgres DB to a local
    tar file for nginx to serve.
    This should run only on the postgres node.
    """

    if deepy.cfg.sync_config.get("deployment_type") != DeploymentType.PRIMARY:
        log_fatal("Exiting, cannot dump config from non-primary cluster")

    deepy.util.lock("config_sync_dump.lock")

    timestamp = arrow.utcnow().format("YYYYMMDDHHmmss")
    with staging_area(timestamp) as staging_dir:
        _dump_local_config(staging_dir)
        _dump_postgres(staging_dir)

        _package_tarfile(f"{timestamp}_{_get_current_version()}.tar.gz", staging_dir)

    prune_config()
    regenerate_manifest()


def _get_latest(api_key, primary):
    config_api_url = f"https://{primary}/api/config_sync/dumps/latest/"
    params = {"api_key": api_key}
    try:
        result = requests.get(config_api_url, params, verify=False, timeout=30)
    except requests.exceptions.Timeout:
        log_fatal(f"get_config: timeout connecting to {primary}")
    except requests.exceptions.RequestException:
        log_fatal(f"get_config: could not connect to {primary}")
    if result.status_code != 200:
        log_fatal(f"get_config: /config_sync/dumps/latest API call to {primary} failed")
    return result.json()["uri"]


def _get_config(api_key, primary, filename):
    """Download config tarball to local and hdfs storage"""

    config_url = f"https://{primary}{filename}"
    params = {"api_key": api_key}
    try:
        config_result = requests.get(
            config_url, params, stream=True, verify=False, timeout=30
        )
    except requests.exceptions.Timeout:
        log_fatal(f"get_config: timeout connecting to {primary}")
    except requests.exceptions.RequestException:
        log_fatal(f"get_config: could not connect to {primary}")
    if config_result.status_code != 200:
        log_fatal(f"get_config: download of {filename} from {primary} failed")
    # save locally and in hdfs
    with deepy.cfg.store.write_file_atomically(
        os.path.join(deepy.cfg.pathman.sync_dir, os.path.basename(filename))
    ) as tmp_filename:
        with open(tmp_filename, "wb") as tmp_file:
            for chunk in config_result.iter_content(chunk_size=8192):
                tmp_file.write(chunk)


@emit_stats
def get_config():
    """Download config from primary into hdfs."""

    if deepy.cfg.sync_config.get("deployment_type") != DeploymentType.SECONDARY:
        log_fatal("Exiting, cannot run get_config from non-secondary cluster")

    deepy.util.lock("config_sync_get.lock")

    try:
        api_key = deepy.cfg.sync_config["primary"]["api_key"]
        primary = deepy.cfg.sync_config["primary"]["hostname"]
    except:
        log_fatal("get_config: failed, api_key or hostname configuration is missing")
    deepy.log.info(
        "config_sync: get_config: starting download of latest config from primary"
    )
    latest = _get_latest(api_key, primary)
    deepy.log.info(f"config_sync: API call made, latest is {latest}")
    _get_config(api_key, primary, latest)
    deepy.log.info(
        f"config_sync: get_config: completed download of latest config {latest} from primary {primary}"
    )
    prune_config()


def _exit_if_not_master(action):
    if not deepy.salty.is_salt_master():
        log_fatal(f"config_sync: {action}: can only run on salt master, exiting")


def _force_sync(action="_force_sync"):
    _exit_if_not_master(action)
    cmd = "deployment_sync.py --config-only"
    if not deepy.salty.cmd_run(cmd):
        log_fatal(f"{action}: '{cmd}' ran with errors")


def _run_pause_roles(action="_run_pause_roles", exclude=None):
    """
    Runs the pause_roles salt script.  Used before loading/changing config to only stop certain processes
    """
    _exit_if_not_master(action)
    stop_cron_cmd = "service cron stop"
    if not deepy.salty.cmd_run(stop_cron_cmd):
        log_fatal(f"{action}: '{stop_cron_cmd}' ran with errors")
    cmd = "state.sls pause_roles"
    if exclude:
        cmd += f" exclude={exclude}"
    if not deepy.salty.salt_run(func=cmd, target_expression="*"):
        log_fatal(f"{action}: '{cmd}' ran with errors")
    return True


def _restart_all(action="_restart_all"):
    """
    Restart all processes, for use after loading/changing config.
    """
    _run_pause_roles(action=action)
    if not _start_all():
        log_fatal("config_sync: processes did not restart cleanly during failover")


def _start_all():
    start_daemons_cmd = "supervisorctl start all"
    start_daemons_result = deepy.salty.cmd_run(start_daemons_cmd)
    start_cron_cmd = "service cron start"
    start_cron_result = deepy.salty.cmd_run(start_cron_cmd)
    deepy.exabgp.config.client.Client().send_exabgp_update_cmd("restart_children")
    return start_cron_result and start_daemons_result


def _refresh_cache() -> None:
    """
    Refreshes the redis cache with new values after reloading new files from the Primary deployment.
    Since some caches are only refreshed on update (e.g. dimensions), this needs to be called periodically
    to update the redis cache, as no updates actually occur on the secondary deployment.
    """
    reload_dimensions_cmd = "reload_cache.py --dimensions"
    result = subprocess.run(
        reload_dimensions_cmd.split(),
    )
    if result.returncode != 0:
        deepy.log.error("failed to refresh dimensions cache")


def _update_bgp_sessions() -> None:
    ddb = deepy.dimensions.ddb.get_local_ddb([deepy.pipedream.DIMENSION_ROUTER])
    handle = ddb[deepy.pipedream.DIMENSION_ROUTER]
    with deepy.defender.dfdb.defender_session_factory(
        force_disable_read_only_mode=True
    ).get_session_handler() as session:
        for position in handle.get_positions().values():
            bgp = deepy.util.recursive_get(position, "router", "bgp")
            if bgp is None:
                continue
            for bgp_session in bgp:
                config_bgp.update_session(bgp_session, session)


def _merge_slice_file(new_slice_json):
    with deepy.cfg.store.simple_update_json(
        deepy.cfg.slice_file, force_disable_read_only_mode=True
    ) as slice_json:
        slice_json.update(
            {
                key: val
                for key, val in new_slice_json.items()
                if key not in LOCAL_SLICE_FIELDS
            }
        )


def _merge_routers_file(new_routers_json):
    # get the existing data
    routers_dim_filename = os.path.join(deepy.cfg.dimensions_dir, "router.json.gz")
    old_routers_json = deepy.cfg.store.simple_load_json(routers_dim_filename)

    # update the new data with the existing local_ips/router_id where appropriate
    positions = deepy.util.recursive_get(
        old_routers_json, "dimensions", "115", "positions", default={}
    )
    for position_id, position in positions.items():
        old_bgp_entries = deepy.util.recursive_get(
            position, "router", "bgp", default=[]
        )
        if old_bgp_entries is None:
            continue
        for old_bgp_entry in old_bgp_entries:
            # check if the position_id + name entry exists in the new routers file
            # if so replace the new local_ip with the old one
            new_bgp_entries = deepy.util.recursive_get(
                new_routers_json,
                "dimensions",
                "115",
                "positions",
                position_id,
                "router",
                "bgp",
                default=[],
            )
            if new_bgp_entries is None:
                continue
            for new_bgp_entry in new_bgp_entries:
                if (
                    new_bgp_entry.get("name") is not None
                    and (new_bgp_entry.get("name") == old_bgp_entry.get("name"))
                    and new_bgp_entry.get("available_for")
                    == old_bgp_entry.get("available_for")
                ):
                    new_bgp_entry["local_ip"] = old_bgp_entry["local_ip"]
                    new_bgp_entry["router_id"] = config_bgp.get_router_id(old_bgp_entry)
                    break

    # save the updated new routers json
    deepy.cfg.store.simple_save_json(
        new_routers_json,
        routers_dim_filename,
        push=True,
        force_disable_read_only_mode=True,
    )


def _load_local_config_file(config_tar, tarinfo):
    with deepy.cfg.store.write_file_atomically(
        os.path.join(deepy.cfg.cache_dir, tarinfo.name),
        force_disable_read_only_mode=True,
    ) as tmp_filename:
        output_dir = os.path.dirname(tmp_filename)
        # Remove the directory from the tarinfo member name so that it extracts directly
        # to the tmp dir. Otherwise `write_file_atomically` will ignore the directory.
        tarinfo.name = os.path.basename(tarinfo.name)
        config_tar.extract(tarinfo, path=output_dir)


def _is_fatal_error(restore_error: str):
    """
    Function to parse stderr of a pg_restore operation to identify if there is at least 1 error outside of known errors that are harmless.
    pg_restore: error: could not execute query: ERROR:  cannot drop type public."HealthStatusDeviceTopic_status" because other objects depend on it
    and
    pg_restore: error: could not execute query: ERROR:  type "HealthStatusDeviceTopic_status" already exists
    are expected errors given HealthStatus tables are excluded from pg_dump and are therefore not cleaned at the destination prior to a restore.
    Args:
        restore_error: Error message to parse

    Returns:Boolean
        indicating whether or not there was at least 1 fatal error
    """
    p = re.compile(
        '^pg_restore: error: could not execute query: ERROR:(  cannot drop type .*$|  type ".*" already exists)'
    )
    for line in restore_error.split("\n"):
        if not line.startswith("pg_restore: error") or p.match(line):
            print(line)
            continue
        elif line.startswith(
            "pg_restore: error: could not execute query: ERROR:  cannot drop function public.update_last_modified_column"
        ) or line.startswith(
            'pg_restore: error: could not execute query: ERROR:  function "update_last_modified_column" already exists with same argument types'
        ):
            print(line)
            continue
        else:
            return True
    return False


def _load_postgres(config_tar, tarinfo, filename):
    db_to_load = filename.split(".")[0]
    with staging_area("tmp_postgres_load") as staging_dir:
        os.mkdir(staging_dir)
        config_tar.extract(tarinfo, path=staging_dir)

        host_name = deepy.sql_helper.get_sql_host()

        db_name = f"{db_to_load}_{deepy.cfg.deployment_id}"
        result = subprocess.run(
            [
                "pg_restore",
                "--clean",
                "--if-exists",
                "--no-owner",
                f"--dbname=postgresql://{deepy.cfg.database_username}:"
                f"{deepy.cfg.database_password}@{host_name}/{db_name}",
                f"{os.path.join(staging_dir, tarinfo.name)}",
            ],
            capture_output=True,
            text=True,
        )

    if result.returncode != 0:
        if _is_fatal_error(result.stderr):
            log_fatal(
                f"failed to restore postgres db {db_name} restore result: {result}"
            )
        else:
            deepy.log.info(
                f"Logging the following expected/harmless errors that occurred during restore of {db_name}: {result.stderr}"
            )


@emit_stats
def load_config(skip_restart=False):
    """Load config from latest cached tarfile"""

    if deepy.cfg.sync_config.get("deployment_type") != DeploymentType.SECONDARY:
        log_fatal("Exiting, cannot run load_config from non-secondary cluster")

    deepy.util.lock("config_sync_load.lock")

    latest_encrypted = max(
        [
            os.path.basename(dump_file)
            for dump_file in glob.glob(f"{deepy.cfg.pathman.sync_dir}/*.tar.gz.enc")
        ],
        default=None,
    )
    if not latest_encrypted:
        log_fatal(
            f"load_config: failed, no encrypted tarfiles found in {deepy.cfg.pathman.sync_dir}"
        )

    dump_version = latest_encrypted.replace(".tar.gz.enc", "").split("_")[1]
    if _get_current_version() != dump_version:
        log_fatal(
            "load_config: latest config not compatible with current pipedream version"
        )

    # Encrypted file path
    latest_encrypted_config_path = os.path.join(
        deepy.cfg.pathman.sync_dir, latest_encrypted
    )

    # Decrypted file path
    with tempfile.TemporaryDirectory(dir=deepy.cfg.data_tmp) as temp_dir_path:
        decrypted_latest_file = os.path.join(
            temp_dir_path, os.path.splitext(latest_encrypted)[0]
        )
        _decrypt_file(latest_encrypted_config_path, decrypted_latest_file)

        # Clear out files from some directories
        for local_config_dir in ["context", "dimensions", "sql_dimensions"]:
            for filename in os.listdir(
                os.path.join(deepy.cfg.cache_dir, local_config_dir)
            ):
                if (
                    local_config_dir == "dimensions"
                    and filename in DIMENSIONS_DIR_FILES_TO_IGNORE + ["router.json.gz"]
                ):
                    continue
                filepath = os.path.join(deepy.cfg.cache_dir, local_config_dir, filename)
                if os.path.isfile(filepath):
                    os.remove(filepath)

        deepy.log.info(
            "load_config: beginning load of config from " f"{decrypted_latest_file}"
        )

        skip_restart or _run_pause_roles(exclude="states.exabgp.pause")

        with tarfile.open(decrypted_latest_file) as local_latest:
            for tarinfo in local_latest.getmembers():
                if tarinfo.isdir():
                    continue

                location, basename = os.path.split(tarinfo.name)
                deepy.log.debug(f"Attempting to load {tarinfo.name}")

                if basename == "slice.json":
                    _merge_slice_file(json.load(local_latest.extractfile(tarinfo)))
                elif basename.endswith(".sql"):
                    _load_postgres(local_latest, tarinfo, basename)
                elif (
                    location == "dimensions"
                    and basename in DIMENSIONS_DIR_FILES_TO_IGNORE
                ):
                    continue
                elif location == "dimensions" and basename == "router.json.gz":
                    _merge_routers_file(
                        json.load(gzip.open(local_latest.extractfile(tarinfo)))
                    )
                elif any(
                    location.startswith(local_config_dir)
                    for local_config_dir in [
                        "config",
                        "context",
                        "dimensions",
                        "sql_dimensions",
                    ]
                ):
                    try:
                        _load_local_config_file(local_latest, tarinfo)
                    except StoreHDFSRefuseZeroLength:
                        deepy.log.warning(
                            f"Not loading {tarinfo.name}, file is zero-length"
                        )
                elif location == "" and basename == "dimension_mappings.json.gz":
                    _load_local_config_file(local_latest, tarinfo)
                else:
                    deepy.log.warning(f"Not loading unexpected file {tarinfo.name}")

    _update_bgp_sessions()
    skip_restart or _start_all()
    _refresh_cache()
    deepy.log.info(
        f"load_config: finished loading config from {latest_encrypted_config_path}"
    )


def _make_active(skip_restart=False):
    current_mode = deepy.cfg.sync_config["mode"]
    if current_mode == ConfigSyncMode.ACTIVE:
        deepy.log.info("config_sync: deployment is already active, exiting")
        return
    deepy.log.info(
        f"config_sync: transitioning deployment from {current_mode} to active"
    )
    deepy.cfg.sync_config["mode"] = ConfigSyncMode.ACTIVE
    deepy.config_sync.update_sync_config(deepy.cfg.sync_config)
    _force_sync("make_active")
    skip_restart or _restart_all("make_active")
    deepy.log.info("config_sync: deployment now in active mode")


def make_active():
    _configd_is_up()
    deployment_type = deepy.cfg.sync_config["deployment_type"]

    if deployment_type == DeploymentType.PRIMARY:
        _make_active()
        _clear_events()
    elif deployment_type == DeploymentType.SECONDARY:
        if not _run_pause_roles():
            deepy.log.warn(
                "config_sync: processes did not stop cleanly during make active"
            )
        try:
            get_config()
        except SystemExit as err:
            deepy.log.warn(str(err))
        load_config(skip_restart=True)
        _make_active(skip_restart=True)
        if not _start_all():
            deepy.log.warn(
                "config_sync: processes did not restart cleanly during make active"
            )
        _clear_events()


def _make_passive():
    current_mode = deepy.cfg.sync_config["mode"]
    if current_mode == ConfigSyncMode.PASSIVE:
        deepy.log.info("config_sync: deployment is already passive, exiting")
        return
    deepy.log.info(
        f"config_sync: transitioning deployment from {current_mode} to passive"
    )
    deepy.cfg.sync_config["mode"] = ConfigSyncMode.PASSIVE
    deepy.config_sync.update_sync_config(deepy.cfg.sync_config)
    _force_sync("make_passive")
    _restart_all("make_passive")
    deepy.log.info("config_sync: deployment now in passive mode")


def make_passive():
    _configd_is_up()
    _clear_events(pre_enable_action=_make_passive)


def make_upgrade():
    current_mode = deepy.cfg.sync_config["mode"]
    if current_mode == ConfigSyncMode.UPGRADE:
        deepy.log.info("config_sync: deployment is already upgrade, exiting")
        return
    deepy.log.info(
        f"config_sync: transitioning deployment from {current_mode} to upgrade"
    )
    deepy.cfg.sync_config["mode"] = ConfigSyncMode.UPGRADE
    deepy.config_sync.update_sync_config(deepy.cfg.sync_config)
    _restart_all("make_upgrade")
    deepy.log.info("config_sync: deployment now in upgrade mode")


def make_primary(args=None):
    restart_required = False
    if deepy.cfg.sync_config["deployment_type"] != DeploymentType.PRIMARY:
        restart_required = True
        deepy.log.info(
            "config_sync: transitioning deployment from secondary to primary"
        )
    deepy.cfg.sync_config["deployment_type"] = DeploymentType.PRIMARY
    if args:
        deepy.cfg.sync_config["secondary"] = {"hostname": args[0], "api_key": args[1]}
    else:
        deepy.cfg.sync_config["secondary"] = None
    if restart_required:
        del deepy.cfg.sync_config["primary"]
    deepy.config_sync.update_sync_config(deepy.cfg.sync_config)
    restart_required and _restart_all("make_primary")
    deepy.log.info("config_sync: deployment now primary")


def make_secondary(args=None):
    restart_required = False
    if deepy.cfg.sync_config["deployment_type"] != DeploymentType.SECONDARY:
        restart_required = True
        deepy.log.info(
            "config_sync: transitioning deployment from primary to secondary"
        )
    deepy.cfg.sync_config["deployment_type"] = DeploymentType.SECONDARY
    if args:
        deepy.cfg.sync_config["primary"] = {"hostname": args[0], "api_key": args[1]}
    else:
        deepy.cfg.sync_config["primary"] = None
    if restart_required:
        del deepy.cfg.sync_config["secondary"]
    deepy.config_sync.update_sync_config(deepy.cfg.sync_config)
    restart_required and _restart_all("make_secondary")
    deepy.log.info("config_sync: deployment now secondary")


def update_cron(job, schedule):
    try:
        deepy.config_sync.update_cron(job, schedule)
    except deepy.config_sync.Error as error:
        log_fatal(str(error))


def _confirm_failover(deployment_type, current_mode, desired_mode):
    print(f"Deployment is currently {deployment_type} {current_mode}")
    return input(
        f"Enter 'make-{deployment_type}-{desired_mode}' to initiate failover: "
    )


def _clear_events(pre_enable_action: Callable = None):
    """Clear devices (filters) and shutdown any active events or mitigations,
    run any action (such as make_passive) that needs to occur before re-enabling policies, and then re-enable policies
    """
    # clear devices using route provided by acld.py, affects
    # netconf filters and bgp announcements on routers
    session_factory = deepy.defender.dfdb.defender_session_factory(
        force_disable_read_only_mode=True
    )
    config_event_kafka_producer = deepy.config.events.subscribe_config_producers()
    try:
        force_cleanup_dnf(session_factory)
    except Exception as err:
        deepy.log.warn(f"config_sync: Failed to force cleanup ACLs: {str(err)}")
    with session_factory.get_session_handler() as session:
        # end any defender events and related mitigations, by temporarily disabling
        # then re-enabling any active defender policies
        ddb = deepy.dimensions.ddb.get_ddb()
        active_policies = [
            policy
            for policy in session.query(Policy).filter_by(enabled=True, deleted=0)
        ]
        for policy in active_policies:
            policies.update_policy(session, ddb, policy.id, {"enabled": False})
            emit_policy_update(session, [policy], producer=config_event_kafka_producer)

        # clear radware by ending any ongoing protections
        devices = session.query(RadwareDevice).all()
        for device in devices:
            try:
                device.clear_protections()
            except Exception as err:
                deepy.log.warn(
                    f"config_sync: failed to clear protections on radware device {device.id}: {str(err)}"
                )

        # Call the mode change operation (e.g. make_passive) now that policies have been disabled, but before they're re-enabled
        if pre_enable_action:
            pre_enable_action()

        # Re-enable the polices that were deactivated to turn off events/mitigations
        for policy in active_policies:
            policies.update_policy(session, ddb, policy.id, {"enabled": True})
            emit_policy_update(session, [policy], producer=config_event_kafka_producer)


def _configd_is_up():
    try:
        ddb = deepy.dimensions.ddb.get_ddb()
        ddb.wait_until_available()
    except ConfigdUnreachable:
        log_fatal(
            "failover: aborted, cannot perform a failover while configd is unreachable"
        )


def failover():
    """This command requires interactive input."""
    if not deepy.salty.is_salt_master():
        log_fatal("failover: aborted, must be run on salt master")
    modes = [ConfigSyncMode.ACTIVE, ConfigSyncMode.PASSIVE]
    deployment_type = deepy.cfg.sync_config["deployment_type"]
    current_mode = deepy.cfg.sync_config["mode"]
    if current_mode == ConfigSyncMode.UPGRADE:
        log_fatal(
            "failover: aborted, cannot perform a failover while deployment is in upgrade mode"
        )
    desired_mode = modes[(modes.index(current_mode) + 1) % 2]
    response = _confirm_failover(deployment_type, current_mode, desired_mode)
    if response != f"make-{deployment_type}-{desired_mode}":
        log_fatal("failover: aborted, incorrect response")

    make_active() if desired_mode == ConfigSyncMode.ACTIVE else make_passive()

    deepy.log.info(
        f"config_sync: failover of {deployment_type} deployment to {desired_mode} state complete"
    )


def sync_config():
    """Convenience function that combines get_config and load_config (used by deepshell)."""
    try:
        get_config()
    except:
        log_fatal("sync_config: get failed, aborting before load_config")
    load_config()


def regenerate_manifest():
    """Create/update the manifest.json file."""
    encrypted_tarfiles = sorted(
        map(os.path.basename, glob.glob(f"{deepy.cfg.pathman.sync_dir}/*.tar.gz.enc"))
    )
    manifest = {"latest": encrypted_tarfiles[-1], "available": encrypted_tarfiles}
    with deepy.cfg.store.write_file_atomically(
        deepy.cfg.pathman.sync_manifest
    ) as tmp_path:
        with open(tmp_path, "w") as outfile:
            json.dump(manifest, outfile)


def log_fatal(message):
    deepy.log.error(f"config_sync: {message}")
    raise SystemExit(1)


def main():
    args = parse_args()
    if args.verbose:
        deepy.log.init(level="DEBUG")


    if args.show_config:
        show_config()
    elif args.dump_config:
        dump_config()
    elif args.prune_config:
        prune_config()
    elif args.get_config:
        get_config()
    elif args.load_config:
        load_config()
    elif args.sync_config:
        sync_config()
    elif args.make_active:
        make_active()
    elif args.make_passive:
        make_passive()
    elif args.make_upgrade:
        make_upgrade()
    elif args.make_primary:
        if args.hostname and args.api_key:
            make_primary((args.hostname, args.api_key))
        else:
            make_primary()
    elif args.make_secondary:
        if args.hostname and args.api_key:
            make_secondary((args.hostname, args.api_key))
        else:
            make_secondary()
    elif args.cron:
        update_cron(args.job, args.schedule)
    elif args.failover:
        failover()


if __name__ == "__main__":
    main()
