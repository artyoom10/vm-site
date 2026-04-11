# VM RGU — веб-интерфейс

Корень для **DocumentRoot** (или копируйте содержимое `vm-site/` на сервер как корень сайта).

## Структура

| Путь | Назначение |
|------|------------|
| `index.php` | SPA после входа |
| `login.php` | Страница входа (Supabase) |
| `api/` | `dataset.php`, `auth.php`, `report.php`, `refresh.php` |
| `includes/` | `bootstrap.php`, сессия, заголовки |
| `storage/` | `config.php`, датасет JSON (не отдаётся напрямую веб-сервером — вынесите за пределы public при жёсткой политике) |
| `css/app.css` | Собранные стили (раньше были `styles` + `components` + `responsive` + `theme-dark-shell`) |
| `js/` | `data-loader.js`, `router.js`, `utils.js`, страницы в `js/pages/` |

## Первый запуск после `git clone`

1. Скопируйте конфиг: `storage/config.example.php` → `storage/config.php` и задайте Supabase URL и anon key **или** переменные окружения `SUPABASE_URL`, `SUPABASE_ANON_KEY`.
2. Положите датасет в `storage/multihost_openvas_dataset.json` (или поправьте путь в конфиге).

## Деплой

1. На сервере: `SUPABASE_URL`, `SUPABASE_ANON_KEY`, при необходимости `VM_AUTH_DISABLED=0`, `VM_COOKIE_SECURE=1`, `REPORT_API_BASE`.
2. Настройте PHP с `curl` и cookies.

## Git

Файл `storage/config.php` в репозиторий не попадает (секреты). В индексе только `storage/config.example.php`.
