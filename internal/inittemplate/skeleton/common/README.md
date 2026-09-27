# << .Name >> — репозиторий шаблона tplaiter

Это репозиторий шаблона, совместимый с [tplaiter](https://github.com/tplAIter/tplaiter).
Он сгенерирован командой `tplaiter init-template << .Name >>` и содержит рабочий
минимальный пример со всем инструментарием: манифест настроек, дерево `files/`,
генераторы, ai-config и плейбуки окружения.

## Быстрый старт мейнтейнера

```sh
tplaiter lint-template         # селфтест: рендер всех «угловых» комбинаций настроек
```

Правьте `template.manifest.yaml` (группы настроек, commands, hooks), дерево
`files/` (шаблоны проекта) и `ai-config/` (правила для AI-ассистентов).
Конвенции доработки описаны в `ai-config/rules/00-base.md`.

## Публикация версий

Версии шаблона — это git-теги (SemVer):

```sh
git tag v0.1.0
git push origin v0.1.0
```

- single-repo (один шаблон в корне): тег вида `vX.Y.Z`;
- multi-repo (`repo.manifest.yaml` + подкаталоги): тег вида `<template-name>/vX.Y.Z`.

`tplaiter new <ref>` без `@version` берёт старший стабильный тег; при отсутствии
тегов — HEAD ветки (с предупреждением).

## Подключение репозитория

```sh
tplaiter repo add mycompany <url-этого-репозитория>
tplaiter template list
tplaiter new mycompany/<< .Name >> my-project
```

## CI

`.github/workflows/template.yml` запускает `tplaiter lint-template` и матрицу
рендера по угловым комбинациям (`--combo`). Держите проверки зелёными перед
публикацией тега.

Документация tplaiter: https://github.com/tplAIter/tplaiter
