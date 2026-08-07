-- ============================================================
--  Smart Campus — регистрация педагогов с лендинга
--  PostgreSQL 14+
--
--  Правила, заложенные в схему:
--    * телефон = логин, на него приходит код подтверждения;
--    * ИИН уникален: один человек — один аккаунт;
--    * «обычный учитель» регистрируется сам (source = 'self');
--    * педагоги УК и школ заводятся администратором через АУП
--      (source = 'aup'), самостоятельная регистрация им запрещена;
--    * пробный доступ — 3 анализа на 30 дней, дальше блокировка.
--
--  ПЕРСОНАЛЬНЫЕ ДАННЫЕ. ИИН, ФИО и телефон граждан РК по закону
--  «О персональных данных» хранятся на серверах в Казахстане.
--  ИИН здесь лежит в двух видах: iin_hash для поиска и проверки
--  уникальности, iin_enc — шифротекст для случаев, когда номер
--  нужно показать. Открытым текстом ИИН не хранить.
-- ============================================================

BEGIN;

-- ---------- Справочники ----------

CREATE TYPE org_kind    AS ENUM ('binom', 'farabi', 'school');
CREATE TYPE reg_source  AS ENUM ('self', 'aup');
CREATE TYPE acct_status AS ENUM ('active', 'blocked', 'archived');

CREATE TABLE organization (
    id          bigserial PRIMARY KEY,
    kind        org_kind    NOT NULL,
    name        text        NOT NULL,
    city        text        NOT NULL,
    bin         varchar(12),                    -- БИН организации, если нужен
    is_active   boolean     NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE organization IS
    'УК и школы. Заполняется через АУП; лендинг только читает этот список.';

-- ---------- Педагоги ----------

CREATE TABLE teacher (
    id           bigserial PRIMARY KEY,

    -- логин и связь
    phone        varchar(11) NOT NULL,          -- 7XXXXXXXXXX, только цифры
    email        citext      NOT NULL,

    -- личные данные
    full_name    text        NOT NULL,
    iin_hash     bytea       NOT NULL,          -- SHA-256 от 12 цифр + серверная соль
    iin_enc      bytea       NOT NULL,          -- шифротекст ИИН (pgcrypto/KMS)

    -- профиль
    city         text        NOT NULL,
    subject      text        NOT NULL,
    experience   text        NOT NULL,          -- диапазон: 'lt1', '1-3', ... , '30+'
    category     text        NOT NULL,          -- none | moderator | expert | researcher | master

    -- откуда пришёл
    source       reg_source  NOT NULL,
    org_id       bigint      REFERENCES organization(id),

    status       acct_status NOT NULL DEFAULT 'active',
    phone_verified_at timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT teacher_phone_uniq UNIQUE (phone),
    CONSTRAINT teacher_iin_uniq   UNIQUE (iin_hash),
    CONSTRAINT teacher_phone_fmt  CHECK (phone ~ '^7[0-9]{10}$'),

    -- сам зарегистрировался — значит без организации;
    -- пришёл из АУП — организация обязательна
    CONSTRAINT teacher_source_org CHECK (
        (source = 'self' AND org_id IS NULL) OR
        (source = 'aup'  AND org_id IS NOT NULL)
    )
);

CREATE INDEX teacher_org_idx ON teacher (org_id) WHERE org_id IS NOT NULL;

-- ---------- Код подтверждения ----------

CREATE TABLE otp_code (
    id          bigserial PRIMARY KEY,
    phone       varchar(11) NOT NULL,
    code_hash   bytea       NOT NULL,           -- сам код не хранить
    payload     jsonb       NOT NULL,           -- анкета до подтверждения номера
    attempts    smallint    NOT NULL DEFAULT 0,
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT otp_attempts_cap CHECK (attempts <= 5)
);

-- живой код на номер должен быть один
CREATE UNIQUE INDEX otp_active_uniq
    ON otp_code (phone) WHERE consumed_at IS NULL;

CREATE INDEX otp_expiry_idx ON otp_code (expires_at);

COMMENT ON COLUMN otp_code.payload IS
    'Анкета с лендинга. Удаляется вместе со строкой после подтверждения или истечения срока.';

-- ---------- Пробный доступ ----------

CREATE TABLE trial (
    teacher_id     bigint PRIMARY KEY REFERENCES teacher(id) ON DELETE CASCADE,
    analyses_limit smallint    NOT NULL DEFAULT 3,
    analyses_used  smallint    NOT NULL DEFAULT 0,
    started_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL DEFAULT now() + interval '30 days',
    blocked_at     timestamptz,

    CONSTRAINT trial_used_range CHECK (analyses_used BETWEEN 0 AND analyses_limit)
);

COMMENT ON TABLE trial IS
    'Квота считается здесь, на сервере. Клиентский счётчик обходится очисткой браузера.';

-- Доступен ли пробный период прямо сейчас
CREATE OR REPLACE FUNCTION trial_is_open(p_teacher_id bigint)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT t.blocked_at IS NULL
       AND t.expires_at > now()
       AND t.analyses_used < t.analyses_limit
    FROM trial t
    WHERE t.teacher_id = p_teacher_id;
$$;

-- ---------- Списание анализа ----------

CREATE TABLE lesson_analysis (
    id          bigserial PRIMARY KEY,
    teacher_id  bigint      NOT NULL REFERENCES teacher(id) ON DELETE CASCADE,
    lesson_id   bigint,                          -- ссылка на урок в основной системе
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX lesson_analysis_teacher_idx ON lesson_analysis (teacher_id, created_at DESC);

-- Один анализ — минус единица квоты; на нуле выставляется блокировка
CREATE OR REPLACE FUNCTION spend_trial_analysis()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    t trial%ROWTYPE;
BEGIN
    SELECT * INTO t FROM trial WHERE teacher_id = NEW.teacher_id FOR UPDATE;

    IF NOT FOUND THEN
        RETURN NEW;                              -- платный тариф: квота не действует
    END IF;

    IF t.blocked_at IS NOT NULL
       OR t.expires_at <= now()
       OR t.analyses_used >= t.analyses_limit THEN
        RAISE EXCEPTION 'trial_exhausted'
            USING HINT = 'Пробный период исчерпан: нужен платный тариф';
    END IF;

    UPDATE trial
       SET analyses_used = analyses_used + 1,
           blocked_at = CASE
               WHEN analyses_used + 1 >= analyses_limit THEN now()
               ELSE blocked_at
           END
     WHERE teacher_id = NEW.teacher_id;

    RETURN NEW;
END;
$$;

CREATE TRIGGER lesson_analysis_spends_quota
    BEFORE INSERT ON lesson_analysis
    FOR EACH ROW EXECUTE FUNCTION spend_trial_analysis();

-- ---------- Согласие на обработку данных ----------

CREATE TABLE consent (
    id          bigserial PRIMARY KEY,
    teacher_id  bigint      NOT NULL REFERENCES teacher(id) ON DELETE CASCADE,
    document    text        NOT NULL,            -- версия политики, например 'pdp-2026-08'
    granted_at  timestamptz NOT NULL DEFAULT now(),
    ip          inet,
    user_agent  text
);

COMMENT ON TABLE consent IS
    'Факт согласия на обработку персональных данных. Без записи здесь регистрацию не завершать.';

COMMIT;
