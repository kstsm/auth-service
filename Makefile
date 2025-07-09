build:
	docker build --tag 'auth-service' .

run:
	docker run 'auth-service'