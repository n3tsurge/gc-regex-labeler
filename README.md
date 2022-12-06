# Guardicore Regular Expression Labeler

Labels assets based on Regular expressions using the Centra API

## Future Features

- [x] Continuous labeling
- [x] Support for labeling based on values in lists (e.g. using the MAC address of a machine)
- [x] Multi-field criteria rules (must match expression across all fields to label)
- [x] Dockerized version for continuous labeling
- [ ] Hot reload of the config.yml file to load new rules without relaunching the container/script


## Usage

1. Clone the repository `git clone git@github.com:n3tsurge/gc-regex-labeler.git`
2. Install the dependencies `pip install`
3. Setup your labeling rules in `config.yml`
4. Run `pipenv run python gc-regex-labeler.py`

```text
$ pipenv run python .\gc-regex-labeler.py -h
usage: gc-regex-labeler.py [-h] [--config CONFIG] [--gc-management-url GC_MANAGEMENT_URL] [--report] [--rules] [--service] [--wait-interval WAIT_INTERVAL] [--verbose-log VERBOSE_LOG] [-u USER] [-p] [--check-dupes]
                           [--check-missing CHECK_MISSING [CHECK_MISSING ...]] [--csv-missing-only] [--label-missing] [--skip-deleted] [--export-csv] [--csv-label-keys CSV_LABEL_KEYS [CSV_LABEL_KEYS ...]]
                           [--csv-file-name CSV_FILE_NAME] [--email-report] [--email-to EMAIL_TO [EMAIL_TO ...]] [--email-subject EMAIL_SUBJECT] [--email-from EMAIL_FROM] [--smtp-server SMTP_SERVER] [--check-duplicate-ips]
                           [--deactivate-old-assets] [--asset-age ASSET_AGE] [--preview-deactivate] [--ignore-tls IGNORE_TLS]

options:
  -h, --help            show this help message and exit
  --config CONFIG       The path to the configuration file
  --gc-management-url GC_MANAGEMENT_URL
                        Guardicore management URL
  --report              Report only mode, previews the labels that would be created and the number of assets within
  --rules               Shows all the rules in the system and exits
  --service             Runs the Guardicore Regex Labeler in a loop with a wait interval
  --wait-interval WAIT_INTERVAL
                        Wait interval (seconds) between runs when running as a service
  --verbose-log VERBOSE_LOG
                        Turning this on will output verbose logs
  -u USER, --user USER  Guardicore username
  -p, --password        Prompt for the Guardicore password
  --check-dupes         Prints out all the assets that have multiple values for a key
  --check-missing CHECK_MISSING [CHECK_MISSING ...]
                        Identify assets missing a label for a certain key or list of keys
  --csv-missing-only    When exporting a CSV report only the assets with missing labels will be output
  --label-missing       Will label assets missing labels with the --check-missing flag with a label Labels Missing: Yes
  --skip-deleted        Do not return deleted assets
  --export-csv          Export the data to a csv
  --csv-label-keys CSV_LABEL_KEYS [CSV_LABEL_KEYS ...]
                        Which label keys to export
  --csv-file-name CSV_FILE_NAME
                        The path where to save the CSV file
  --email-report        Whether to e-mail the exported CSV
  --email-to EMAIL_TO [EMAIL_TO ...]
                        Who to send the exported CSV to
  --email-subject EMAIL_SUBJECT
                        The subject of the email for sending the CSV
  --email-from EMAIL_FROM
                        From addresss for sending email reports
  --smtp-server SMTP_SERVER
                        The SMTP server to use
  --check-duplicate-ips
                        Returns a JSON doc that highlights IP overlap
  --deactivate-old-assets
                        Will indicate to the tool that it should deactivate old assets in the conosle
  --asset-age ASSET_AGE
                        How long (in days) should the asset be offline to be deactivated using the --deactivate-old-assets flag
  --preview-deactivate  Will print out which assets will be deactivated and how many
  --ignore-tls IGNORE_TLS
                        Ignores TLS issues when calling the API
```

![example.png](example.png)

## Labeling Rules

```yaml
domain-specific-workstations:
    enabled: false
    patterns:
      guest_agent_details.hostname: # The field to match expressions on
        - "^.*\\.example\\.com"
      guest_agent_details.os_details.os_display_name: "^.*Windows [^(Server)].*$"
    labels:
      Asset Type: Workstation
      Organization: Example
    source_field_labels:
      Operating System: guest_agent_details.os_details.os_display_name  # Set the label key with the value of this field if prior patterns match
```
