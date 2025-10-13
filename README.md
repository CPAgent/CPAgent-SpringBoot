# CPAgent Spring Boot Application

`.env.example`를 복사해서 `.env` 파일을 만들고 환경변수를 설정합니다.

`docker compose up -d` 명령어로 PostgreSQL 컨테이너를 실행합니다.

## Windows (cmd)

```cmd
gradlew.bat bootRun --args="--spring.profiles.active=postgres"
```

## macOS/Linux

```bash
SPRING_PROFILES_ACTIVE=postgres ./gradlew bootRun
```
