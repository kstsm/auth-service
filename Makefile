up:
	docker-compose up -d

down:
	docker-compose down

swagger:
	swag init -g main.go

run:
	swag init -g main.go && go run main.go