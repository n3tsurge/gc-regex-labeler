import csv
import json
import logging
import re
import smtplib
import threading
from argparse import ArgumentParser
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate
from getpass import getpass
from os.path import basename
from queue import Queue
from time import sleep

import urllib3
from pyaml_env import parse_config

from guardicore.centra import CentraAPI

urllib3.disable_warnings()


def send_email(send_from, send_to, subject, body, files=[], server="127.0.0.1", as_html=False):
    """
    Sends an e-mail message to multiple recipients with multiple attachments
    """

    msg = MIMEMultipart('alternative')
    msg['From'] = send_from
    msg['To'] = COMMASPACE.join(send_to)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject

    if as_html:
        msg.attach(MIMEText(body, 'html'))
    else:
        msg.attach(MIMEText(body, 'plain'))

    for f in files:
        filename = basename(f)
        with open(f, 'rb') as fh:
            part = MIMEApplication(fh.read(), name=filename)

        part['Content-Disposition'] = f"attachment; filename={filename}"
        msg.attach(part)

    smtp = smtplib.SMTP(server)
    smtp.sendmail(send_from, send_to, msg.as_string())
    smtp.close()


def load_config(path="config.yml"):
    """
    Loads the configuration file for the application
    and returns a configuration object for consumption in
    other areas
    """
    config_error = False
    config = parse_config(path)

    return config


def get_nested(message, *args):
    ''' Iterates over nested fields to get the final desired value '''
    if args and message:
        element = args[0]
        if element:
            value = message.get(element)
            return value if len(args) == 1 else get_nested(value, *args[1:])


def match_all(pattern, target):

    m = False
    if target:
        if isinstance(pattern, list):
            m = any(re.match(p, target, re.IGNORECASE) for p in pattern)
        else:
            m = bool(re.match(pattern, target, re.IGNORECASE))
    return m


def process_label(label_queue, centra):
    while not label_queue.empty():
        label_data = label_queue.get()
        key = label_data['key']
        value = label_data['value']
        vms = label_data['vms']
        success = centra.create_static_label(key, value, vms)
        if success:
            logging.info(f"Labeled {len(vms)} assets with {key}: {value}")
        else:
            logging.error(
                f"Failed to label {len(vms)} assets with {key}: {value}")


if __name__ == "__main__":
    # Set the logging format
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)

    # Parse script parameters
    parser = ArgumentParser()
    parser.add_argument('--config', help="The path to the configuration file",
                        default="config.yml", required=False)
    parser.add_argument('--gc-management-url',
                        help="Guardicore management URL", required=False)
    parser.add_argument('--report', help="Report only mode, previews the labels that would be created and the number of assets within",
                        action="store_true", required=False)
    parser.add_argument('--rules', help="Shows all the rules in the system and exits",
                        action="store_true", required=False)
    parser.add_argument('--service', help="Runs the Guardicore Regex Labeler in a loop with a wait interval",
                        action="store_true", required=False)
    parser.add_argument(
        '--wait-interval', help="Wait interval (seconds) between runs when running as a service", required=False, type=int)
    parser.add_argument(
        '--verbose-log', help="Turning this on will output verbose logs", required=False)
    parser.add_argument(
        '-u', '--user', help="Guardicore username", required=False)
    parser.add_argument('-p', '--password', help="Prompt for the Guardicore password",
                        required=False, action="store_true")
    parser.add_argument(
        '--check-dupes', help="Prints out all the assets that have multiple values for a key", action="store_true")
    parser.add_argument(
        '--check-missing', help="Identify assets missing a label for a certain key or list of keys", nargs="+")
    parser.add_argument(
        '--csv-missing-only', help="When exporting a CSV report only the assets with missing labels will be output", action="store_true")
    parser.add_argument(
        '--label-missing', help="Will label assets missing labels with the --check-missing flag with a label Labels Missing: Yes", action="store_true")
    parser.add_argument(
        '--skip-deleted', help="Do not return deleted assets", action="store_true")
    parser.add_argument(
        '--export-csv', help="Export the data to a csv", action="store_true")
    parser.add_argument('--csv-label-keys',
                        help="Which label keys to export", nargs="+")
    parser.add_argument('--csv-file-name',
                        help="The path where to save the CSV file")
    parser.add_argument(
        '--email-report', help="Whether to e-mail the exported CSV", action="store_true")
    parser.add_argument(
        '--email-to', help="Who to send the exported CSV to", nargs="+")
    parser.add_argument('--email-subject',
                        help="The subject of the email for sending the CSV")
    parser.add_argument(
        '--email-from', help="From addresss for sending email reports")
    parser.add_argument('--smtp-server', help="The SMTP server to use")
    parser.add_argument(
        '--ignore-tls', help="Ignores TLS issues when calling the API")
    args = parser.parse_args()

    # Load the configuration
    config = load_config(path=args.config)

    if config['guardicore']['report_only']:
        args.report = True

    if args.user:
        config['guardicore']['username'] = args.user

    if args.password:
        config['guardicore']['password'] = getpass(prompt="Password: ")

    if args.gc_management_url:
        config['guardicore']['management_url'] = args.gc_management_url

    if args.email_report:
        config['global']['email_report'] = args.email_report

    if args.email_to:
        config['global']['email_to'] = args.email_to

    if args.email_subject:
        config['global']['email_subject'] = args.email_subject

    if args.email_from:
        config['global']['email_from'] = args.email_from

    if args.smtp_server:
        config['global']['smtp_server'] = args.smtp_server

    if args.rules:
        print("{:<30} {:<10} {:<10}".format("Name", "Status", "Labels"))
        print("-"*55)
        for rule in config['rules']:
            rule_status = "Enabled" if config['rules'][rule]['enabled'] else "Disabled"
            rule_labels = ", ".join(
                f"{key}: {config['rules'][rule]['labels'][key]}" for key in config['rules'][rule]['labels'])
            print("{:<30} {:<10} {:<10}".format(
                rule, rule_status, rule_labels))
        exit(0)

    if args.csv_missing_only:
        logging.warning("Resulting CSV will only contain assets missing label values due to --csv-missing-only")

    # Authenticate to Guardicore
    logging.info("Authenticating to Guardicore")
    centra = CentraAPI(
        management_url=config['guardicore']['management_url'], verify_tls=config['guardicore']['verify_tls'])

    try:
        centra.authenticate(
            username=config['guardicore']['username'], password=config['guardicore']['password'])
    except Exception as e:
        logging.error(e)
        exit(1)

    if 'wait_interval' in config['global'] and not args.wait_interval:
        wait_interval = int(config['global']['wait_interval'])
    else:
        wait_interval = args.wait_interval

    if args.check_dupes:
        logging.info("Fetching all assets from Guardicore Centra")
        assets = centra.list_assets(limit=1000)
        for asset in assets:
            label_stats = {}
            bad_keys = {}
            for label in asset['labels']:
                key = label['key']
                if key in label_stats:
                    label_stats[key].append(label['value'])
                else:
                    label_stats[key] = [label['value']]

            for key in label_stats:
                if len(label_stats[key]) > 1:
                    bad_keys[key] = label_stats[key]

            if len(bad_keys) > 0:
                logging.warning(
                    f"{asset['name']} has multiple labels for {bad_keys}")

        exit(1)

    if args.check_missing:
        logging.info("Fetching all assets from Guardicore Centra")
        if args.skip_deleted:
            logging.info("Skipping assets that are off/deleted")
            assets = centra.list_assets(limit=1000, status="on")
        else:
            assets = centra.list_assets(limit=1000)
        for asset in assets:
            bad_keys = []
            for key in args.check_missing:
                if not any(l for l in asset['labels'] if key == l['key']):
                    bad_keys.append(key)

            if len(bad_keys) > 0:
                print(
                    f"{asset['name']} is missing the following label keys {bad_keys}")

        exit(1)

    if args.export_csv:

        if not args.csv_file_name:
            logging.error('The --csv-file-name parameter is required.')
            exit(1)

        logging.info('Fetching all assets from Guardicore Centra')

        if args.skip_deleted:
            logging.info("Skipping assets that are off/deleted")
            assets = centra.list_assets(limit=1000, status="on")
        else:
            assets = centra.list_assets(limit=1000)

        csv_headers = ['asset_name', 'status'] + args.csv_label_keys
        rows = []

        for asset in assets:
            row = {
                'asset_name': asset['name'],
                'status': asset['status']
            }
            missing_label = False
            for key in args.csv_label_keys:

                # If the asset has the label
                if any(l for l in asset['labels'] if key == l['key']):

                    # Find all the labels for this key
                    for label in asset['labels']:
                        if label['key'] == key:

                            # If the label has already been added and is duplicate append the dupe
                            # else add the new value
                            if key in row and isinstance(row[key], list):
                                row[key].append(label['value'])
                            else:
                                row[key] = [label['value']]

                else:
                    row[key] = ''
                    missing_label = True

            # Merge and flatten all list fields
            for key in args.csv_label_keys:
                row[key] = '\n'.join(row[key])

            if args.csv_missing_only:
                if missing_label:
                    rows.append(row)
            else:
                rows.append(row)

        with open(args.csv_file_name, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_headers)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)

        if config['global']['email_report'] == 42:

            body = f"""<html><head></head><body><h1>Assets Missing Key Labels Report</h1><p><i>This report was automatically generated by the Guardicore Regex Labeling Tool.</i><br><br><b>IMPORTANT</b>: Assets missing these labels may not get proper policy and may be at an elevated exposure level or may be incorrectly blocking traffic.<br><br>The report contains assets missing one of the following labels: <ul>"""
            for key in args.csv_label_keys:
                body += f"<li>{key}</li>"

            body += """</ul></p><h2>How to read this report</h2><p>The best method for reading this report is to filter on <b>status</b> on, then filter for any of the label keys where the key is blank.  Label keys will be represented as columns in the CSV</p></body></html>"""

            send_email(send_from=config['global']['email_from'],
                       send_to=config['global']['email_to'],
                       subject=config['global']['email_subject'],
                       body=body,
                       files=[args.csv_file_name],
                       server=config['global']['smtp_server'],
                       as_html=config['global']['email_as_html'])

        exit(0)

    # Run each labeling rule
    active_rules = [r for r in config['rules']
                    if config['rules'][r]['enabled']]
    while True:

        ID_FIELD = 'id'

        # Fetch all the agents
        logging.info("Fetching all assets from Guardicore Centra")

        assets = centra.list_assets(limit=1000, status="on")

        # Create an empty dictionary to store all the labels that were processed
        # to provide summary metrics at the end of the run
        labels = {}

        for rule in active_rules:
            logging.info(f"Running label rule {rule}")

            rule_config = config['rules'][rule]

            patterns = rule_config['patterns']
            condition = rule_config['condition'] if 'condition' in rule_config else 'all'

            for asset in assets:
                matched = False

                if condition == "all":
                    matched = all(match_all(patterns[p], get_nested(
                        asset, *p.split('.'))) for p in patterns)
                if condition == "any":
                    matched = any(match_all(patterns[p], get_nested(
                        asset, *p.split('.'))) for p in patterns)

                if matched:

                    if 'debug' in rule_config and rule_config['debug']:
                        logging.info(f"Rule {rule} matched on {asset['name']}")

                    for key in rule_config['labels']:
                        label_value = rule_config['labels'][key]

                        if not args.report and args.verbose_log:
                            logging.info(
                                f"Labeling {asset['name']} with {key}: {label_value}")

                        if f"{key}: {label_value}" in labels:
                            labels[f"{key}: {label_value}"].append(
                                asset[ID_FIELD])
                        else:
                            labels[f"{key}: {label_value}"] = [asset[ID_FIELD]]

                    if 'source_field_labels' in rule_config:
                        for key in rule_config['source_field_labels']:
                            label_value = get_nested(
                                asset, *rule_config['source_field_labels'][key].split('.'))

                            if not args.report and args.verbose_log:
                                logging.info(
                                    f"Labeling {asset['name']} with {key}: {label_value}")

                            if f"{key}: {label_value}" in labels:
                                labels[f"{key}: {label_value}"].append(
                                    asset[ID_FIELD])
                            else:
                                labels[f"{key}: {label_value}"] = [
                                    asset[ID_FIELD]]

        # Dedupe the assets in each label
        if args.report:
            labels = {l: list(set(labels[l])) for l in labels}
            print(json.dumps({l: len(labels[l]) for l in labels}, indent=4))
        else:
            label_queue = Queue()

            for l in labels:
                key_value_pair = l.split(': ')
                key = key_value_pair[0]
                value = key_value_pair[1]
                #vms = labels[l]
                vms = list(set(labels[l]))
                label_queue.put({'key': key, 'value': value, 'vms': vms})

            workers = []
            for i in range(0, 5):
                p = threading.Thread(target=process_label,
                                     daemon=True, args=(label_queue, centra))
                workers.append(p)

            [w.start() for w in workers]
            [w.join() for w in workers]

            #success = centra.create_static_label(key, value, vms)
            # if success:
            #    logging.info(f"Labeled {len(vms)} assets with {key}: {value}")

        # If this is a single run, break out of the loop
        if not args.service:
            break
        else:
            logging.info(f"Sleeping for {wait_interval} seconds.")
            sleep(wait_interval)
