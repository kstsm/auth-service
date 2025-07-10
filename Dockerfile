FROM golang:1.24

WORKDIR /app

COPY . .

RUN go install github.com/swaggo/swag/cmd/swag@latest && \
    swag init -g main.go && \
    go build -o auth-service .

EXPOSE 8080

CMD ["./auth-service"]