## Установка и запуск проекта

### Клонирование репозитория
Для начала работы склонируйте репозиторий в удобную Вам директорию:
```bash
git clone https://github.com/kstsm/auth-service
```

### Настройка переменных окружения
Создайте `.env` файл, скопировав в него значения из `.env.example`, и укажите необходимые параметры.

### Запуск приложения
Команда для запуска проекта через Docker:
```bash
docker-compose -f docker-compose.yml up -d
```

Или используя Makefile:
```bash
make docker-up
```

## Swagger документация

### Запуск Swagger UI с Docker

1. Соберите и запустите проект:
   ```bash
   make docker-build
   make docker-up
   ```

2. Откройте Swagger UI в браузере:
   ```
   http://localhost:8080/swagger/
   ```

### Запуск Swagger UI локально

1. Убедитесь, что у вас установлен Go и swag CLI:
   ```bash
   go install github.com/swaggo/swag/cmd/swag@latest
   ```

2. Сгенерируйте Swagger документацию:
   ```bash
   make swagger
   ```

3. Запустите сервер:
   ```bash
   make dev-run
   ```

4. Откройте Swagger UI в браузере:
   ```
   http://localhost:8080/swagger/
   ```

### Доступные endpoints

- `GET /swagger/` - Swagger UI
- `GET /swagger/doc.json` - Swagger JSON документация
- `POST /token` - Генерация токенов
- `POST /token/refresh` - Обновление токенов
- `GET /me` - Информация о пользователе (требует авторизации)
- `POST /logout` - Деавторизация (требует авторизации)

## Доступные команды Makefile

### Docker команды
- `make docker-build` - Сборка Docker образа
- `make docker-up` - Запуск контейнеров
- `make docker-down` - Остановка контейнеров
- `make docker-logs` - Просмотр логов

### Swagger команды
- `make swagger` - Генерация Swagger документации
- `make swagger-serve` - Генерация документации и запуск сервера

### Команды разработки
- `make dev-build` - Сборка проекта с Swagger
- `make dev-run` - Запуск проекта с Swagger
