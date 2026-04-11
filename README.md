# VM RGU — веб-интерфейс

Корень для **DocumentRoot** (или копируйте содержимое репозитория на сервер как корень сайта).

## Структура

| Путь | Назначение |
|------|------------|
| `index.php` | SPA после входа |
| `login.php` | Страница входа (Supabase) |
| `api/` | `dataset.php`, `auth.php`, `report.php`, `refresh.php` |
| `includes/` | `bootstrap.php`, сессия, заголовки |
| `storage/` | `config.php` (Supabase и пути), датасет JSON |
| `css/app.css` | Собранные стили |
| `js/` | `data-loader.js`, `router.js`, `utils.js`, страницы в `js/pages/` |

## После `git clone`

1. Убедитесь, что в `storage/` есть `multihost_openvas_dataset.json` (в репозитории он уже есть).
2. Авторизация через Supabase (email/пароль на `login.php`). Без токена в cookie доступ к `index.php` и API закрыт. Для локальной разработки без входа можно задать `VM_AUTH_DISABLED=1`.
3. При деплое при необходимости переопределите параметры через переменные окружения (`SUPABASE_URL`, `SUPABASE_ANON_KEY`, `VM_COOKIE_SECURE` и т.д.).

## Деплой

Настройте PHP с поддержкой `curl` и корректной работой cookie (HTTPS → `VM_COOKIE_SECURE=1` при необходимости).
