FROM golang:1.24

WORKDIR ${GOPATH}/auth-service/
COPY . ${GOPATH}/auth-service/

RUN go build -o /build ./ && go clean -cache -modcache

EXPOSE 8080

CMD ["/build"]