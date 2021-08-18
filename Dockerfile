FROM python:3

COPY config.yml.sample /config.yml
COPY gc-regex-labeler.py /
COPY Pipfile /
COPY Pipfile.lock /
COPY guardicore /guardicore

WORKDIR /

RUN pip install --upgrade pip
RUN pip install pipenv
RUN pipenv install

CMD ["pipenv", "run", "python", "gc-regex-labeler.py"]
