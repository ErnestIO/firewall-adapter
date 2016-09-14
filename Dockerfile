FROM golang:1.6.2-alpine

RUN apk add --update git && apk add --update make && rm -rf /var/cache/apk/*

ADD . /go/src/github.com/${GITHUB_ORG:-ernestio}/firewall-adapter
WORKDIR /go/src/github.com/${GITHUB_ORG:-ernestio}/firewall-adapter

RUN make deps && go install

ENTRYPOINT ./entrypoint.sh
