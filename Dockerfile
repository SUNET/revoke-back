FROM golang:1.16

WORKDIR /usr/src/app
COPY . .

RUN go get -d -v ./...
RUN go install -v ./...

EXPOSE 8001

CMD ["revoke-back"]
