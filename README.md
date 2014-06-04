aws_viewer
==========

Installation
----------

```
pip install -r requirements.txt
cp .aws_viewer ~/.aws_viewer
```


###Creating virtualenv(optional)

Do it if you really know why you need it

```
virtualenv ~/virtualenvs/aws_viewer
workon aws_viewer
pip install -r requirements.txt
```

Configuration
----------
Main configuration file is `~/.aws_viewer`
```
[default]
aws_access_key_id = XXX
aws_secret_access_key = XXX
cache_timeout = 120
using_iam_role = false
tags = environment,service,role,version
regions = us-west-2,us-east-1
```

**aws_access_key_id** - amazon access key(ignored if **using_iam_role** is true)
**aws_secret_access_key** - amazon secret access key(ignored if **using_iam_role** is true)
**cache_timeout** - set cache timeout on amazon responce in seconds(optional parameter, default 30 seconds)
**using_iam_role** - set to true to use IAM role
**tags** - which tags print/ask. Mandatory
**regions** - will be appear in interactive mode as an option(default us-west-2 ans us-east-1)

####IAM Support

set `using_iam_role` to `true`

Usage
---------
`python aws_viewer` - interactive mode
`python aws_viewer -a -r us-west-2` - print all instances in 'us-west-2'
`python aws_viewer -a -r us-west-2  -t version,role` - show all instances with tags `role` and `version`(override `tags` from config)
`python aws_viewer -t version,role` - ask about `role` and `version` tags


####Intercative mode(default) example:
```
python aws_viewer.py
Possible options of region
1) us-west-2
2) us-east-1
Please enter option: 1
Possible options of environment
0) ALL
1) development
2) staging
3) production
Please enter option: 3
Possible options of service
0) ALL
1) service1
2) service2
Please enter option: 1
Possible options of role
0) ALL
1) webserver
2) database
Please enter option: 1
Possible options of version
0) ALL
1) 1.0.1
2) 1.0.2
Please enter option: 1
```
produces:
```
--------------------------------------------------------------------------------------------------------------------
| instance_id |    environment |        service |           role |        version |         state |             ip |
--------------------------------------------------------------------------------------------------------------------
|  i-xxxxxxxx |     production |       service1 |        webserver |          1.0.1 |       running |  xx.xx.xx.xx |
|  i-xxxxxxxx |     production |       service1 |        webserver |          1.0.1 |       running |  xx.xx.xx.xx |
--------------------------------------------------------------------------------------------------------------------
| TOTAL: 2 | Running: 2 | Stopped: 0 | Terminated: 0 |
```


Screenshots
---------
`python aws_viewer -t environment,role`
![alt text](http://s29.postimg.org/wvlva4vyv/Foto_Flexer_Photo.jpg)
`python aws_viewer -t environment,role,service,version`
![alt text](http://s9.postimg.org/y2dofqhdb/Foto_Flexer_Photo1.jpg)

