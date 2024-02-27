# nuclei2zap
Simple script to convert Nuclei templates to ZAP scripts. It is made to convert some simple templates into ZAP active scanner scripts, it only supports http templates, defined by requests or raw, also the only supported matchers are status, word and regex so the script won't be able to convert files that uses other matchers. Nuclei supports a great amount of variables, encoders, etc. if the scripts detects any of these on the template it won't convert it, but you can use the `-f` argument to force it to create the file, while it won't work as expected due this (and if it throws an error won't convert it anyways), you could edit the generated file so it works as intended. Also if a template only sends a get requests to the requested URL the script will convert it into a passive scanner script, there is no need to make another request.

# Why?
While Nuclei being far most efficient of making use of the templates made for it I thoght there would be some ocassions where it would be nice to have some active scans on background that uses the current information (mostly session stuff), and while you can just add them at the time of using Nuclei I thought this would be easier. Outside of rare situations I would still recomend using Nuclei ratter than having a ton of active rules running on backgroud.

# Help menu

```
usage: nuclei2zap.py [-h] -t TEMPLATES [-f]

Simple script to convert Nuclei templates a Bchecks to Zap scripts.

optional arguments:
  -h, --help            show this help message and exit
  -t TEMPLATES, --templates TEMPLATES
                        Template file o directory to convert.
  -f, --force           Try to generate a script for the files that can't be converterd completely.
```

# Notes
While I tested that most of the scripts generated work (there are some that uses some extra characteristics that would take some work to handle) I can't asure that everything will work completely fine, so just dont' trust everything that the script generates. Also please do not upload any script generated to the ZAP community scripts repository, the scripts generated are not really optimized and could be improved manually.
