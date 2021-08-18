# Guardicore Regular Expression Labeler

Labels assets based on Regular expressions using the Centra API

## Usage

1. Clone the repository `git clone git@github.com:n3tsurge/gc-regex-labeler.git`
2. Install the dependencies `pip install`
3. Setup your labeling rules in `config.yml`
4. Run `pipenv run python gc-regex-labeler.py`

```text
$ pipenv run python .\gc-regex-labeler.py -h
usage: gc-regex-labeler.py [-h] [--config CONFIG]
                           [--gc-management-url GC_MANAGEMENT_URL] [--report]
                           [-u USER] [-p]

optional arguments:
  -h, --help            show this help message and exit
  --config CONFIG       The path to the configuration file
  --gc-management-url GC_MANAGEMENT_URL
                        Guardicore management URL
  --report              Report only mode, previews the labels that would be
                        created and the number of assets within
  -u USER, --user USER  Guardicore username
  -p, --password        Prompt for the Guardicore password
```

![example.png](example.png)

## Labeling Rules

```yaml
environment-production:
  enabled: true
  sources:
    guest_agent_details.hostname:  # The field on the asset to match on
      pattern: '^\w{3}[L|W|A]P[V|P].*'  # The regular expression to use
      labels:
        Environment: Production  # Label key : value
    label_source_field: Operating System # If set take the value of guest_agent_details.hostname and set it to the Operating System label key
```
