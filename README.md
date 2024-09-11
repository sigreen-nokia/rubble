# Rubble

                             ......                             
                         ...^!~~^::...::..                        
                       .^^:::.....      .::::. :.                 
                           .^^~:.:^:.......:^~~. ...              
                     .....:^75^^7:^.  ...:^^^^~::..^.             
                    .^  .::.?G^Y@7      ::  .^ .   ^.             
                     ::...   .  .      .^.::.~:!~..^              
                       ^~..... ....     ..  ....~ ..              
                       ^. .^~.    .:::      .^. ^.                
                      ^..^^.    .~   :^     .:  :: .              
                    ..^  .::^^^^!^   .: ..:: .:::^.^:             
                   .~^^. ...~~^:: ...^::..~^::.    ::             
                   ^. .::::   ..::...     .   ..   ^:             
                  .^     ^.  ::..      .. ..::^:   ^:             
                  ::   . .^ ^:       .:~~::.  .:   ^.             
                  ^ .  ^~:^^^!.     ^^ :..    ::   ^.             
                  ^ .   .^!^..      ^.   .    ::  .^              
                 .^ . :~^..!:       ^         ^.  .^              
                 .^ .  .   :.      ::   .     ^  ..^              
                 .^ .              ^.   .    ^:   :.              
                 .^ .              ^.   .   .^    ^               
                  ^ .              ^.       ^.   ::               
                  ^..              :.  .   ~^^: .^                
                  ::               .^     ...~. ::                
                  .^  :^          :^~.....::^: .~                 
                   ^:::.^    .^:  .:^^::^~.:~. ^.                 
                    ^.  :: :~: ^:.:~~::...::~^^^                  
                         ^::^  .^:.:: :::^. ^.:                   
                           ::  .   ::  .:   ^.                    
                           ^.  .   ::       ::                    
                          .^   .   ^.   .   :^                    
                      .:::.      ..^... .   .::::...              
                  :::^^..        . ^...         .:^:^.            
                  ~:^.^^^~       .:~:....     :^^~::~:            
                  .:^:~..... ..:::. ....::::.^:::~:^.             
                       :.:.:::.            ......      
      

## What Does Rubble do:

* Rubble is OpenSource and free to use and deploy within your AWS accounts

* Rubble deploys a Deepfield backup server, which then backs up up your deepfield cluster configuration 

* Rubble then emails a report in pdf to show the backup status 

* Rubble is fully automated within a an AWS cloudformation stack. 

* Rubble is configurable. you can modify it using the cloudformation parameters

## Why all the lambda

* aws ec2 instances cost money.

* So we use lamdba to fire up the aws infra, run the scheduled backup then delete itself
 
* Makes it a few dollars a year to run. 

## what does the file email-template.emltpl do

* you can use this as an sample email template. 

* Sent it to anyone and when they click the embedded button, it will deploy the stack into their aws account (not yours)

## What do the files deploy-rubble.sh/delete-rubble.sh do

* You can deploy the cloudformation stack from cli by tunning this file ./deploy-rubble.sh

* ./delete-rubble.sh deletes the cloudformation stack. For people who do not like GUI's

## What do the files make-s3-bucket.sh/delete-ssh-key.sh do

* makes or deletes an s3 bucket for storing the backups. Incase you do not already have one

## Whats do the files debug-node-ssh-on.sh/debug-node-ssh-off.sh do

* The instances come up with no external access at all, only outbound. So you cannot connect to them for debug by default.

* run this file to add or delete an ssh rule in the security groups. It tells you how to then ssh

* logs are here 
* Cloudwatch log groups: rubble-nmap	Logs when generating config backups emails
* Cloudwatch log groups: /aws/lambda/Rubble-NMAPLamdbaSchedulerStack*	The output from the scheduler
* On the nodes: /tmp/node-install.log /var/log/rubble.log /ar/log/cloud*

### Any configuration before you deploy it:

* You just need to Configure an aws ec2 access key into your aws account, the default name is rubble, but you can change it in the cloudformation parameters. 

* All other parameters have sensible defaults to get you started.

* there are helper file you can run if you don't know how to do that ./make-ssh-key.sh  h

### Where are the backups kept ?

* in the parameters you specify an s3 bucket to use for the backups. 

* there are helper scripts to create those if you don't know how 

* ./make-s3-bucket.sh ./delete-s3-bucket.sh

### I don't want to schedule my backup, I just want to run it now and leave the instance up to look around. \n",

* Set parameter [service name]LambdaScheduleStartExpression=null 

* No lambda scheduler will run for that service, 

* Instead the nodes will be fired up straight away and execute a backup.

* The instance will stay up untill you delete the cloudformation stack 

## More details on Emailing Reports:

### Email In General 

* For emailing reports I use msmtp (smtp) and configure it using five stack parameter:
	* EmailServerURL
    * EmailUsername
    * EmailPassword
    * EmailFromAddress
    * EmailToAddress

* This works well with most email smtp services, I've tested with icloud, gmail and AWS SES.
### Gmail 
* To use gmail to send the report, you need to generate an app password and use that rather than youre account password
* Info: https://support.google.com/accounts/answer/185833?p=InvalidSecondFactor&visit_id=637525499216786581-3978521167&rd=1
* google web portal->security->app password->
   	* mail
	* other
	* copy the password and use it as the password for your account

Example: 
```
ParameterKey=EmailServerURL,ParameterValue="smtp.gmail.com" \
ParameterKey=EmailUsername,ParameterValue="my.email@gmail.com" \
ParameterKey=EmailPassword,ParameterValue="yl45fGtfsfwr" \
ParameterKey=EmailFromAddress,ParameterValue="my.email@gmail.com" \
ParameterKey=EmailToAddress,ParameterValue="my.email@gmail.com"
```
### ICloud 
* To use icloud to send the reports again you need create an app password and use that rather than youre account password
* Info: https://support.apple.com/en-gb/HT204397
* Portal: https://appleid.apple.com/account/managei
* In the Security section, click Generate Password below App-Specific Passwords.

Example: 
```
ParameterKey=EmailServerURL,ParameterValue="smtp.mail.me.com" \
ParameterKey=EmailUsername,ParameterValue="my.email@icloud.com" \
ParameterKey=EmailPassword,ParameterValue="jkfk-dfeefds-345fdf-gbsc" \
ParameterKey=EmailFromAddress,ParameterValue="my.email@icloud.com" \
ParameterKey=EmailToAddress,ParameterValue="my.email@icloud.com"
```
### AWS SES
* AWS SES you just have to specify the mail servers, login and password. SES will then forward the report emails.
* For SES emails fordwarded to icloud and gmail to be accepted, there is a lot to setup within your AWS account itself, 
* So that the emails are not seen as junk and dropped. This site gives the gorry details https://www.mailmonitor.com/email-delivery-tips-icloud-users/ 

Example: 
```
ParameterKey=EmailServerURL,ParameterValue="email-smtp.eu-central-1.amazonaws.com" \
ParameterKey=EmailUsername,ParameterValue="AKRGFTHGFG67G7K" \
ParameterKey=EmailPassword,ParameterValue="BKfkjrdoifv79fdyYTW" \
ParameterKey=EmailFromAddress,ParameterValue="my.email@mydomain.com \"
ParameterKey=EmailToAddress,ParameterValue="my.email@mydomain"
```
### Hows it work

* The cloudformation builds a lambda. An auto acaling group. All the required infrastructure.

* The lambda on schedule scales up the autoscaling group to one ec2 instance. 

* The EC2 installs the git repo specified in the cloudformation stack parameter GitRepoURL (this git repo by default)

* The EC2 runs the script specified in cloudformation stack parameter ScriptToRun 

* That script handled the backup of the Deepfield cluster


