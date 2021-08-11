FROM golang:1.16

WORKDIR /usr/src/app

COPY go.* .
RUN go mod download

COPY . .
RUN go install -v ./...

EXPOSE 8001

COPY certs/jwt_tls.crt /usr/local/share/ca-certificates/jwt.crt
RUN chmod 644 /usr/local/share/ca-certificates/jwt.crt && update-ca-certificates

CMD ["revoke-back"]
