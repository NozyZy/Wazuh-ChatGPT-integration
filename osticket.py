#!/var/ossec/framework/python/bin/python3

import json
import sys
import time
import os
import random

try:
    import requests
    from requests.auth import HTTPBasicAuth
except Exception as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

# Global vars
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

print(pwd)
# exit()

json_alert = {}
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")
# Set paths
log_file = "{0}/logs/integrations.log".format(pwd)

def main(args):
    debug("# Starting")
    # Read args
    alert_file_location = args[1]
    apikey = args[2]
    webhook = args[3]
    debug("# API Key")
    debug(apikey)
    debug("# File location")
    debug(alert_file_location)

    # Load alert. Parse JSON object.
    with open(alert_file_location) as alert_file:
        json_alert = json.load(alert_file)
    debug("# Processing alert :")
    debug(json_alert)

    # Request osticket info
    debug(f"# REQUEST  {apikey} ")
    msg = query_api(json_alert, apikey, webhook)


def debug(msg):
    if debug_enabled:
        msg = "{0}: {1}\n".format(now, msg)
    print(msg)
    f = open(log_file, "a")
    f.write('\n' + str(msg))
    f.close()


def query_api(alert, apikey, webhook):

    srcip = alert["agent"]["ip"]
    description = alert["rule"]["description"]
    level = alert["rule"]["level"] 

    # Calling osTicket API Endpoint
    headers = {
        "X-API-Key": apikey,
        "Content-Type": "application/json",
    }

    json_data = {
      "alert": True,
      "autorespond": True,
      "priority": random.randint(1,5)
      "source": "API",
      "name": "Wazuh",
      "email": "wazuh@gmail.com",
      "subject": "Alert level " + str(level),
      "message": description + srcip
    }
    debug(headers)
    debug(json_data)

    response = requests.post(webhook, headers=headers, json=json_data)

    debug("# Response : " + response.text)

    if response.status_code == 200:
        # Create new JSON to add the IP
        ip = {"srcip": srcip}
        new_json = {}
        new_json = response.json()["choices"][0]["message"]
        new_json.update(ip)
        json_response = new_json

        data = json_response
        return data
    else:
        exit(0)

if __name__ == "__main__":
    try:
        # Read arguments
        bad_arguments = False
        if len(sys.argv) >= 4:
            msg = "{0} {1} {2} {3} {4}".format(
                now,
                sys.argv[1],
                sys.argv[2],
                sys.argv[3],
                sys.argv[4] if len(sys.argv) > 4 else "",
            )
            debug_enabled = len(sys.argv) > 4 and sys.argv[4] == "debug"
        else:
            msg = "{0} Wrong arguments".format(now)
            bad_arguments = True

        # Logging the call
        f = open(log_file, "a")
        f.write(str(msg) + "\n")
        f.close()

        if bad_arguments:
            debug("# Exiting: Bad arguments.")
            sys.exit(1)

        # Main function
        main(sys.argv)

    except Exception as e:
        debug(str(e))
        raise
