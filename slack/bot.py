import logging
import os
import re
import boto3

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from slack_sdk.errors import SlackApiError

logging.basicConfig(level=logging.ERROR)

app = App(token=os.environ.get("SLACK_BOT_TOKEN"))
handler = SocketModeHandler(app, os.environ["SLACK_APP_TOKEN"])

regex_pattern = r"Dangling record found in (?P<region>[a-z]+-[a-z]+-\d+) on (?P<domain>\S+) for (?P<ip_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) \(allocation ID: (?P<allocation_id>[a-z0-9-]+)\)"


@app.event("reaction_added")
def handle_reaction(event, say):
    if event["reaction"] == "x":
        message_id = event["item"]["ts"]
        channel = event["item"]["channel"]
        response = app.client.conversations_history(channel=channel, latest=message_id, limit=1)
        message_text = response["messages"][0]["text"]
        match = re.search(regex_pattern, message_text)
        if match:
            region = match.group("region")
            domain = match.group("domain")
            ip_address = match.group("ip_address")
            allocation_id = match.group("allocation_id")
            try:
                ec2 = boto3.resource('ec2', region_name=region)
                response = ec2.meta.client.release_address(AllocationId=allocation_id)
                if response["ResponseMetadata"]["HTTPStatusCode"] == 200:
                    say(f":white_check_mark: Released IP address {ip_address} from {domain} for {allocation_id} in {region}", channel=channel)
            except SlackApiError as error:
                say(f":red_circle: {error}", channel=channel)
            except Exception as error:
                say(f":red_circle: {error}", channel=channel)


if __name__ == "__main__":
    handler.start()
