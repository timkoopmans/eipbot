FROM python:3.9

WORKDIR /code
RUN pip install slack-sdk slack_bolt boto3

COPY . .
CMD ["python", "bot.py"]