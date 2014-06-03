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
aws_secret_key = XXX
aws_secret_access_key = XXX
cache_timeout = 120
using_iam_role = false
tags = environment,service,role,version
```

####IAM Support

set `using_iam_role` to `true`

Usage
---------
`python aws_viewer` - interactive mode
`python aws_viewer -a -r us-west-2` - print all instances in 'us-west-2'
`python aws_viewer -a -r us-west-2  -t version,role` - show all instances with tags `role` and `version`(override `tags` from config)
`python aws_viewer -t version,role` - ask about `role` and `version` tags