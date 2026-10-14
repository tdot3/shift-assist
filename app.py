import os
import sqlite3

from datetime import date, datetime, timedelta
from functools import wraps

from flask import (
    Flask,
    request,
    redirect,
    render_template,
    session,
    flash
)

from dotenv import load_dotenv

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


# ==================================================
# 环境变量
# ==================================================

load_dotenv()


SECRET_KEY = os.getenv(
    "SECRET_KEY"
)

ADMIN_USERNAME = os.getenv(
    "ADMIN_USERNAME"
)

ADMIN_PASSWORD = os.getenv(
    "ADMIN_PASSWORD"
)


if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY が .env に設定されていません"
    )

if not ADMIN_USERNAME:
    raise RuntimeError(
        "ADMIN_USERNAME が .env に設定されていません"
    )

if not ADMIN_PASSWORD:
    raise RuntimeError(
        "ADMIN_PASSWORD が .env に設定されていません"
    )


# ==================================================
# Flask
# ==================================================

app = Flask(__name__)

app.secret_key = SECRET_KEY


# ==================================================
# 工具函数
# ==================================================

def time_to_minutes(time_text):

    hour, minute = map(
        int,
        time_text.split(":")
    )

    return (
        hour * 60
        + minute
    )


def get_db_connection():

    conn = sqlite3.connect(
        "shift.db"
    )

    conn.row_factory = (
        sqlite3.Row
    )

    conn.execute(
        "PRAGMA foreign_keys = ON"
    )

    return conn


# ==================================================
# 数据库初始化
# ==================================================

def init_db():

    conn = get_db_connection()


    # ------------------------------
    # Staff
    # ------------------------------

    conn.execute("""
        CREATE TABLE IF NOT EXISTS staff (

            id INTEGER
            PRIMARY KEY
            AUTOINCREMENT,

            name TEXT
            NOT NULL,

            password_hash TEXT
        )
    """)


    # ------------------------------
    # Shifts
    # ------------------------------

    conn.execute("""
        CREATE TABLE IF NOT EXISTS shifts (

            id INTEGER
            PRIMARY KEY
            AUTOINCREMENT,

            employee_id INTEGER
            NOT NULL,

            shift_date TEXT
            NOT NULL,

            start_time TEXT
            NOT NULL,

            end_time TEXT
            NOT NULL,

            source TEXT
            NOT NULL
            DEFAULT 'manual',

            FOREIGN KEY (
                employee_id
            )

            REFERENCES staff(id)
        )
    """)


    # ------------------------------
    # Availability
    # ------------------------------

    conn.execute("""
        CREATE TABLE IF NOT EXISTS availability (

            id INTEGER
            PRIMARY KEY
            AUTOINCREMENT,

            employee_id INTEGER
            NOT NULL,

            work_date TEXT
            NOT NULL,

            preference_type TEXT
            NOT NULL,

            start_time TEXT,

            end_time TEXT,

            UNIQUE (
                employee_id,
                work_date
            ),

            FOREIGN KEY (
                employee_id
            )

            REFERENCES staff(id)
        )
    """)


    # ------------------------------
    # Staffing Requirements
    # ------------------------------

    conn.execute("""
        CREATE TABLE IF NOT EXISTS staffing_requirements (

            id INTEGER
            PRIMARY KEY
            AUTOINCREMENT,

            work_date TEXT
            NOT NULL,

            start_time TEXT
            NOT NULL,

            end_time TEXT
            NOT NULL,

            required_staff INTEGER
            NOT NULL,

            UNIQUE (
                work_date,
                start_time,
                end_time
            )
        )
    """)


    # ------------------------------
    # Shift Requests
    # ------------------------------

    conn.execute("""
        CREATE TABLE IF NOT EXISTS shift_requests (

            id INTEGER
            PRIMARY KEY
            AUTOINCREMENT,

            employee_id INTEGER
            NOT NULL,

            shift_id INTEGER,

            shift_date TEXT
            NOT NULL,

            original_start_time TEXT
            NOT NULL,

            original_end_time TEXT
            NOT NULL,

            request_type TEXT
            NOT NULL,

            requested_start_time TEXT,

            requested_end_time TEXT,

            reason TEXT,

            status TEXT
            NOT NULL
            DEFAULT 'pending',

            created_at TEXT
            NOT NULL,

            FOREIGN KEY (
                employee_id
            )

            REFERENCES staff(id)

            ON DELETE CASCADE,

            FOREIGN KEY (
                shift_id
            )

            REFERENCES shifts(id)

            ON DELETE SET NULL
        )
    """)


    # ==================================================
    # 旧数据库兼容
    # ==================================================

    staff_columns = conn.execute(
        "PRAGMA table_info(staff)"
    ).fetchall()

    staff_column_names = [
        column["name"]
        for column
        in staff_columns
    ]

    if (
        "password_hash"
        not in staff_column_names
    ):

        conn.execute("""
            ALTER TABLE staff

            ADD COLUMN
            password_hash TEXT
        """)


    shift_columns = conn.execute(
        "PRAGMA table_info(shifts)"
    ).fetchall()

    shift_column_names = [
        column["name"]
        for column
        in shift_columns
    ]

    if (
        "source"
        not in shift_column_names
    ):

        conn.execute("""
            ALTER TABLE shifts

            ADD COLUMN
            source TEXT
            NOT NULL
            DEFAULT 'manual'
        """)


    # ==================================================
    # 旧员工初始PIN
    # ==================================================

    staff_list = conn.execute("""
        SELECT
            id,
            password_hash

        FROM staff
    """).fetchall()


    for staff in staff_list:

        if not staff[
            "password_hash"
        ]:

            password_hash = (
                generate_password_hash(
                    "1234",
                    method="pbkdf2:sha256"
                )
            )

            conn.execute("""
                UPDATE staff

                SET password_hash = ?

                WHERE id = ?
            """, (
                password_hash,
                staff["id"]
            ))


    conn.commit()
    conn.close()


# ==================================================
# 管理者登录检查
# ==================================================

def login_required(f):

    @wraps(f)

    def decorated_function(
        *args,
        **kwargs
    ):

        if (
            "user"
            not in session
        ):

            return redirect(
                "/login"
            )

        return f(
            *args,
            **kwargs
        )

    return decorated_function


# ==================================================
# 员工登录检查
# ==================================================

def employee_login_required(f):

    @wraps(f)

    def decorated_function(
        *args,
        **kwargs
    ):

        if (
            "employee_id"
            not in session
        ):

            return redirect(
                "/employee/login"
            )

        return f(
            *args,
            **kwargs
        )

    return decorated_function


# ==================================================
# 管理者登录
# ==================================================

@app.route(
    "/login",
    methods=[
        "GET",
        "POST"
    ]
)
def login():

    if (
        request.method
        == "POST"
    ):

        username = request.form[
            "username"
        ]

        password = request.form[
            "password"
        ]


        if (
            username
            == ADMIN_USERNAME

            and

            password
            == ADMIN_PASSWORD
        ):

            session.clear()

            session[
                "user"
            ] = username

            return redirect(
                "/dashboard"
            )


        flash(
            "ユーザー名またはパスワードが間違っています"
        )

        return redirect(
            "/login"
        )


    return render_template(
        "login.html"
    )


# ==================================================
# 管理者登出
# ==================================================

@app.route(
    "/logout"
)
def logout():

    session.clear()

    return redirect(
        "/login"
    )


# ==================================================
# 员工登录
# ==================================================

@app.route(
    "/employee/login",
    methods=[
        "GET",
        "POST"
    ]
)
def employee_login():

    if (
        request.method
        == "POST"
    ):

        staff_id_text = (
            request.form[
                "staff_id"
            ].strip()
        )

        pin = request.form[
            "pin"
        ]


        try:

            staff_id = int(
                staff_id_text
            )

        except ValueError:

            flash(
                "スタッフIDまたはPINが正しくありません"
            )

            return redirect(
                "/employee/login"
            )


        conn = (
            get_db_connection()
        )


        staff = conn.execute("""
            SELECT
                id,
                name,
                password_hash

            FROM staff

            WHERE id = ?
        """, (
            staff_id,
        )).fetchone()


        conn.close()


        if (
            staff is None

            or

            not staff[
                "password_hash"
            ]

            or

            not check_password_hash(
                staff[
                    "password_hash"
                ],
                pin
            )
        ):

            flash(
                "スタッフIDまたはPINが正しくありません"
            )

            return redirect(
                "/employee/login"
            )


        session.clear()

        session[
            "employee_id"
        ] = staff["id"]

        session[
            "employee_name"
        ] = staff["name"]


        return redirect(
            "/employee"
        )


    return render_template(
        "employee_login.html"
    )


# ==================================================
# 员工登出
# ==================================================

@app.route(
    "/employee/logout"
)
def employee_logout():

    session.clear()

    return redirect(
        "/employee/login"
    )


# ==================================================
# 员工首页
# ==================================================

@app.route(
    "/employee"
)
@employee_login_required
def employee_home():

    employee_id = (
        session[
            "employee_id"
        ]
    )


    today = date.today()


    display_end = (
        today
        + timedelta(
            days=30
        )
    )


    conn = (
        get_db_connection()
    )


    staff = conn.execute("""
        SELECT
            id,
            name

        FROM staff

        WHERE id = ?
    """, (
        employee_id,
    )).fetchone()


    if (
        staff is None
    ):

        conn.close()

        session.clear()

        return redirect(
            "/employee/login"
        )


    shifts = conn.execute("""
        SELECT
            shifts.id,

            shifts.shift_date,

            shifts.start_time,

            shifts.end_time,

            shifts.source,

            (
                SELECT
                    shift_requests.id

                FROM shift_requests

                WHERE
                    shift_requests.shift_id
                    = shifts.id

                    AND

                    shift_requests.status
                    = 'pending'

                LIMIT 1

            ) AS pending_request_id

        FROM shifts

        WHERE
            shifts.employee_id = ?

            AND

            shifts.shift_date >= ?

            AND

            shifts.shift_date <= ?

        ORDER BY
            shifts.shift_date,
            shifts.start_time
    """, (

        employee_id,

        today.isoformat(),

        display_end.isoformat()

    )).fetchall()


    availability_list = (
        conn.execute("""
            SELECT
                work_date,

                preference_type,

                start_time,

                end_time

            FROM availability

            WHERE
                employee_id = ?

                AND

                work_date >= ?

            ORDER BY
                work_date

            LIMIT 10
        """, (

            employee_id,

            today.isoformat()

        )).fetchall()
    )


    request_history = (
        conn.execute("""
            SELECT
                id,

                shift_date,

                original_start_time,

                original_end_time,

                request_type,

                requested_start_time,

                requested_end_time,

                reason,

                status,

                created_at

            FROM shift_requests

            WHERE
                employee_id = ?

            ORDER BY
                id DESC

            LIMIT 10
        """, (
            employee_id,
        )).fetchall()
    )


    conn.close()


    return render_template(

        "employee_home.html",

        staff=staff,

        shifts=shifts,

        availability_list=(
            availability_list
        ),

        request_history=(
            request_history
        ),

        today=(
            today.isoformat()
        ),

        display_end=(
            display_end.isoformat()
        )
    )


# ==================================================
# 员工休假 / 时间变更申请
# ==================================================

@app.route(
    "/employee/request/<int:shift_id>",
    methods=[
        "GET",
        "POST"
    ]
)
@employee_login_required
def employee_shift_request(
    shift_id
):

    employee_id = (
        session[
            "employee_id"
        ]
    )


    conn = (
        get_db_connection()
    )


    shift = conn.execute("""
        SELECT
            shifts.id,

            shifts.employee_id,

            shifts.shift_date,

            shifts.start_time,

            shifts.end_time,

            staff.name

        FROM shifts

        JOIN staff

        ON
            shifts.employee_id
            = staff.id

        WHERE
            shifts.id = ?

            AND

            shifts.employee_id = ?
    """, (

        shift_id,

        employee_id

    )).fetchone()


    if (
        shift is None
    ):

        conn.close()

        flash(
            "対象のシフトが見つかりません"
        )

        return redirect(
            "/employee"
        )


    # ==================================================
    # 24小时前截止
    # ==================================================

    shift_start_datetime = (
        datetime.strptime(
            (
                shift[
                    "shift_date"
                ]
                + " "
                + shift[
                    "start_time"
                ]
            ),
            "%Y-%m-%d %H:%M"
        )
    )


    remaining_time = (
        shift_start_datetime
        - datetime.now()
    )


    if (
        remaining_time
        <= timedelta(
            hours=24
        )
    ):

        conn.close()

        flash(
            "勤務開始24時間前を過ぎているため、"
            "通常の変更申請はできません。"
            "管理者へ直接連絡してください。"
        )

        return redirect(
            "/employee"
        )


    # ==================================================
    # 同一班次的待处理申请
    # ==================================================

    pending = conn.execute("""
        SELECT id

        FROM shift_requests

        WHERE
            shift_id = ?

            AND

            status = 'pending'
    """, (
        shift_id,
    )).fetchone()


    if (
        request.method
        == "POST"
    ):


        if (
            pending is not None
        ):

            conn.close()

            flash(
                "このシフトには既に申請中の変更があります"
            )

            return redirect(
                "/employee"
            )


        request_type = (
            request.form[
                "request_type"
            ]
        )


        reason = (
            request.form.get(
                "reason",
                ""
            ).strip()
        )


        requested_start_time = None

        requested_end_time = None


        # ==================================================
        # 休假
        # ==================================================

        if (
            request_type
            == "leave"
        ):

            requested_start_time = None

            requested_end_time = None


        # ==================================================
        # 时间变更
        # ==================================================

        elif (
            request_type
            == "change"
        ):

            requested_start_time = (
                request.form.get(
                    "requested_start_time",
                    ""
                )
            )

            requested_end_time = (
                request.form.get(
                    "requested_end_time",
                    ""
                )
            )


            if (
                not requested_start_time

                or

                not requested_end_time
            ):

                conn.close()

                flash(
                    "変更後の開始時間と終了時間を入力してください"
                )

                return redirect(
                    f"/employee/request/{shift_id}"
                )


            if (
                time_to_minutes(
                    requested_end_time
                )

                <=

                time_to_minutes(
                    requested_start_time
                )
            ):

                conn.close()

                flash(
                    "終了時間は開始時間より後に設定してください"
                )

                return redirect(
                    f"/employee/request/{shift_id}"
                )


            if (
                time_to_minutes(
                    requested_start_time
                )

                <

                time_to_minutes(
                    shift[
                        "start_time"
                    ]
                )

                or

                time_to_minutes(
                    requested_end_time
                )

                >

                time_to_minutes(
                    shift[
                        "end_time"
                    ]
                )
            ):

                conn.close()

                flash(
                    "変更後の勤務時間は、"
                    "現在のシフト時間内で設定してください"
                )

                return redirect(
                    f"/employee/request/{shift_id}"
                )


            if (
                requested_start_time
                == shift[
                    "start_time"
                ]

                and

                requested_end_time
                == shift[
                    "end_time"
                ]
            ):

                conn.close()

                flash(
                    "現在の勤務時間と同じです"
                )

                return redirect(
                    f"/employee/request/{shift_id}"
                )


        else:

            conn.close()

            flash(
                "申請内容が正しくありません"
            )

            return redirect(
                f"/employee/request/{shift_id}"
            )


        # ==================================================
        # 保存申请
        # ==================================================

        conn.execute("""
            INSERT INTO shift_requests (

                employee_id,

                shift_id,

                shift_date,

                original_start_time,

                original_end_time,

                request_type,

                requested_start_time,

                requested_end_time,

                reason,

                status,

                created_at
            )

            VALUES (
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                'pending', ?
            )
        """, (

            employee_id,

            shift["id"],

            shift[
                "shift_date"
            ],

            shift[
                "start_time"
            ],

            shift[
                "end_time"
            ],

            request_type,

            requested_start_time,

            requested_end_time,

            reason,

            datetime.now().strftime(
                "%Y-%m-%d %H:%M"
            )

        ))


        conn.commit()

        conn.close()


        flash(
            "申請を送信しました"
        )


        return redirect(
            "/employee"
        )


    conn.close()


    return render_template(
        "employee_request.html",
        shift=shift
    )


# ==================================================
# 取得会受申请影响的必要人数条件
# ==================================================

def get_affected_requirements(
    conn,
    request_item
):

    requirements = (
        conn.execute("""
            SELECT
                work_date,

                start_time,

                end_time,

                required_staff

            FROM staffing_requirements

            WHERE
                work_date = ?

            ORDER BY
                start_time
        """, (
            request_item[
                "shift_date"
            ],
        )).fetchall()
    )


    affected = []


    for requirement in requirements:


        original_covers = (

            request_item[
                "original_start_time"
            ]

            <=

            requirement[
                "start_time"
            ]

            and

            request_item[
                "original_end_time"
            ]

            >=

            requirement[
                "end_time"
            ]
        )


        if (
            not original_covers
        ):

            continue


        after_covers = False


        if (
            request_item[
                "request_type"
            ]
            == "change"
        ):

            after_covers = (

                request_item[
                    "requested_start_time"
                ]

                <=

                requirement[
                    "start_time"
                ]

                and

                request_item[
                    "requested_end_time"
                ]

                >=

                requirement[
                    "end_time"
                ]
            )


        if (
            not after_covers
        ):

            affected.append(
                requirement
            )


    return affected


# ==================================================
# 计算批准后缺员
# ==================================================

def calculate_request_shortage(
    conn,
    request_item
):

    affected_requirements = (
        get_affected_requirements(
            conn,
            request_item
        )
    )


    shortage_total = 0


    for requirement in (
        affected_requirements
    ):


        assigned_count = (
            conn.execute("""
                SELECT
                    COUNT(
                        DISTINCT employee_id
                    ) AS count

                FROM shifts

                WHERE
                    shift_date = ?

                    AND

                    start_time <= ?

                    AND

                    end_time >= ?
            """, (

                requirement[
                    "work_date"
                ],

                requirement[
                    "start_time"
                ],

                requirement[
                    "end_time"
                ]

            )).fetchone()[
                "count"
            ]
        )


        assigned_after = max(
            assigned_count - 1,
            0
        )


        shortage = max(

            requirement[
                "required_staff"
            ]

            - assigned_after,

            0
        )


        shortage_total += (
            shortage
        )


    return shortage_total


# ==================================================
# 自动寻找替代候补
# ==================================================

def find_replacement_candidates(
    conn,
    request_item
):

    affected_requirements = (
        get_affected_requirements(
            conn,
            request_item
        )
    )


    if (
        not affected_requirements
    ):

        return (
            [],
            None,
            None
        )


    # ==================================================
    # 需要补上的时间
    # ==================================================

    target_start = min(

        item[
            "start_time"
        ]

        for item
        in affected_requirements
    )


    target_end = max(

        item[
            "end_time"
        ]

        for item
        in affected_requirements
    )


    target_duration = (

        time_to_minutes(
            target_end
        )

        -

        time_to_minutes(
            target_start
        )
    )


    # ==================================================
    # 从勤務希望中找候补
    # ==================================================

    candidate_rows = (
        conn.execute("""
            SELECT
                staff.id,

                staff.name,

                availability.start_time
                AS available_start,

                availability.end_time
                AS available_end,

                (
                    SELECT
                        COUNT(*)

                    FROM shifts
                    AS all_shifts

                    WHERE
                        all_shifts.employee_id
                        = staff.id

                ) AS total_shift_count

            FROM staff

            JOIN availability

            ON
                availability.employee_id
                = staff.id

            WHERE
                staff.id != ?

                AND

                availability.work_date
                = ?

                AND

                availability.preference_type
                = 'available'

                AND

                availability.start_time
                <= ?

                AND

                availability.end_time
                >= ?

                AND NOT EXISTS (

                    SELECT 1

                    FROM shifts
                    AS conflict_shift

                    WHERE
                        conflict_shift.employee_id
                        = staff.id

                        AND

                        conflict_shift.shift_date
                        = ?

                        AND

                        conflict_shift.start_time
                        < ?

                        AND

                        conflict_shift.end_time
                        > ?
                )

            ORDER BY
                total_shift_count ASC,

                staff.id ASC
        """, (

            request_item[
                "employee_id"
            ],

            request_item[
                "shift_date"
            ],

            target_start,

            target_end,

            request_item[
                "shift_date"
            ],

            target_end,

            target_start

        )).fetchall()
    )


    candidates = []


    # ==================================================
    # 1日总工时不得超过8小时
    # ==================================================

    for candidate in (
        candidate_rows
    ):


        same_day_shifts = (
            conn.execute("""
                SELECT
                    start_time,
                    end_time

                FROM shifts

                WHERE
                    employee_id = ?

                    AND

                    shift_date = ?
            """, (

                candidate[
                    "id"
                ],

                request_item[
                    "shift_date"
                ]

            )).fetchall()
        )


        current_minutes = 0


        for shift in (
            same_day_shifts
        ):

            current_minutes += (

                time_to_minutes(
                    shift[
                        "end_time"
                    ]
                )

                -

                time_to_minutes(
                    shift[
                        "start_time"
                    ]
                )
            )


        if (
            current_minutes
            + target_duration
            <= 480
        ):

            candidates.append({

                "id":
                    candidate[
                        "id"
                    ],

                "name":
                    candidate[
                        "name"
                    ],

                "available_start":
                    candidate[
                        "available_start"
                    ],

                "available_end":
                    candidate[
                        "available_end"
                    ],

                "total_shift_count":
                    candidate[
                        "total_shift_count"
                    ],

                "current_minutes":
                    current_minutes
            })


    return (

        candidates,

        target_start,

        target_end
    )


# ==================================================
# 应用员工申请
# ==================================================

def apply_shift_request(
    conn,
    request_item
):


    # ==================================================
    # 休假
    # ==================================================

    if (
        request_item[
            "request_type"
        ]
        == "leave"
    ):

        if (
            request_item[
                "shift_id"
            ]
        ):

            conn.execute("""
                DELETE FROM shifts

                WHERE
                    id = ?

                    AND

                    employee_id = ?
            """, (

                request_item[
                    "shift_id"
                ],

                request_item[
                    "employee_id"
                ]

            ))


    # ==================================================
    # 时间变更
    # ==================================================

    elif (
        request_item[
            "request_type"
        ]
        == "change"
    ):

        if (
            request_item[
                "shift_id"
            ]
        ):

            conn.execute("""
                UPDATE shifts

                SET
                    start_time = ?,

                    end_time = ?

                WHERE
                    id = ?

                    AND

                    employee_id = ?
            """, (

                request_item[
                    "requested_start_time"
                ],

                request_item[
                    "requested_end_time"
                ],

                request_item[
                    "shift_id"
                ],

                request_item[
                    "employee_id"
                ]

            ))


# ==================================================
# 管理者：申请管理
# ==================================================

@app.route(
    "/requests"
)
@login_required
def request_management():

    conn = (
        get_db_connection()
    )


    request_list = (
        conn.execute("""
            SELECT
                shift_requests.id,

                shift_requests.employee_id,

                shift_requests.shift_id,

                shift_requests.shift_date,

                shift_requests.original_start_time,

                shift_requests.original_end_time,

                shift_requests.request_type,

                shift_requests.requested_start_time,

                shift_requests.requested_end_time,

                shift_requests.reason,

                shift_requests.status,

                shift_requests.created_at,

                staff.name

            FROM shift_requests

            JOIN staff

            ON
                shift_requests.employee_id
                = staff.id

            ORDER BY

                CASE

                    WHEN
                        shift_requests.status
                        = 'pending'

                    THEN 0

                    ELSE 1

                END,

                shift_requests.id DESC
        """).fetchall()
    )


    result = []


    for item in (
        request_list
    ):


        shortage_after = 0

        candidates = []

        replacement_start = None

        replacement_end = None


        if (
            item[
                "status"
            ]
            == "pending"
        ):


            shortage_after = (
                calculate_request_shortage(
                    conn,
                    item
                )
            )


            if (
                shortage_after > 0
            ):

                (
                    candidates,

                    replacement_start,

                    replacement_end

                ) = (
                    find_replacement_candidates(
                        conn,
                        item
                    )
                )


        result.append({

            "id":
                item["id"],

            "employee_id":
                item[
                    "employee_id"
                ],

            "name":
                item[
                    "name"
                ],

            "shift_date":
                item[
                    "shift_date"
                ],

            "original_start_time":
                item[
                    "original_start_time"
                ],

            "original_end_time":
                item[
                    "original_end_time"
                ],

            "request_type":
                item[
                    "request_type"
                ],

            "requested_start_time":
                item[
                    "requested_start_time"
                ],

            "requested_end_time":
                item[
                    "requested_end_time"
                ],

            "reason":
                item[
                    "reason"
                ],

            "status":
                item[
                    "status"
                ],

            "created_at":
                item[
                    "created_at"
                ],

            "shortage_after":
                shortage_after,

            "candidates":
                candidates,

            "replacement_start":
                replacement_start,

            "replacement_end":
                replacement_end
        })


    conn.close()


    return render_template(
        "requests.html",
        request_list=result
    )


# ==================================================
# 普通批准
# ==================================================

@app.route(
    "/requests/<int:request_id>/approve",
    methods=[
        "POST"
    ]
)
@login_required
def approve_request(
    request_id
):

    conn = (
        get_db_connection()
    )


    request_item = (
        conn.execute("""
            SELECT *

            FROM shift_requests

            WHERE
                id = ?

                AND

                status = 'pending'
        """, (
            request_id,
        )).fetchone()
    )


    if (
        request_item is None
    ):

        conn.close()

        flash(
            "申請が見つからないか、すでに処理されています"
        )

        return redirect(
            "/requests"
        )


    apply_shift_request(
        conn,
        request_item
    )


    conn.execute("""
        UPDATE shift_requests

        SET
            status = 'approved'

        WHERE
            id = ?
    """, (
        request_id,
    ))


    conn.commit()

    conn.close()


    flash(
        "申請を承認しました"
    )


    return redirect(
        "/requests"
    )


# ==================================================
# 批准 + 自动安排替代人员
# ==================================================

@app.route(
    "/requests/<int:request_id>/approve-replace/<int:staff_id>",
    methods=[
        "POST"
    ]
)
@login_required
def approve_with_replacement(
    request_id,
    staff_id
):

    conn = (
        get_db_connection()
    )


    request_item = (
        conn.execute("""
            SELECT *

            FROM shift_requests

            WHERE
                id = ?

                AND

                status = 'pending'
        """, (
            request_id,
        )).fetchone()
    )


    if (
        request_item is None
    ):

        conn.close()

        flash(
            "申請が見つからないか、すでに処理されています"
        )

        return redirect(
            "/requests"
        )


    (
        candidates,

        target_start,

        target_end

    ) = (
        find_replacement_candidates(
            conn,
            request_item
        )
    )


    candidate_ids = [

        candidate[
            "id"
        ]

        for candidate
        in candidates
    ]


    if (
        staff_id
        not in candidate_ids

        or

        target_start is None

        or

        target_end is None
    ):

        conn.close()

        flash(
            "このスタッフは現在、代替候補として利用できません"
        )

        return redirect(
            "/requests"
        )


    replacement_staff = (
        conn.execute("""
            SELECT
                id,
                name

            FROM staff

            WHERE
                id = ?
        """, (
            staff_id,
        )).fetchone()
    )


    # 原员工申请生效
    apply_shift_request(
        conn,
        request_item
    )


    # 替代员工排班
    conn.execute("""
        INSERT INTO shifts (

            employee_id,

            shift_date,

            start_time,

            end_time,

            source
        )

        VALUES (
            ?, ?, ?, ?, ?
        )
    """, (

        staff_id,

        request_item[
            "shift_date"
        ],

        target_start,

        target_end,

        "manual"

    ))


    # 更新申请状态
    conn.execute("""
        UPDATE shift_requests

        SET
            status = 'approved'

        WHERE
            id = ?
    """, (
        request_id,
    ))


    conn.commit()

    conn.close()


    flash(
        f"申請を承認し、"
        f"{replacement_staff['name']}さんを"
        f"代替スタッフとして配置しました"
    )


    return redirect(
        "/requests"
    )


# ==================================================
# 拒绝申请
# ==================================================

@app.route(
    "/requests/<int:request_id>/reject",
    methods=[
        "POST"
    ]
)
@login_required
def reject_request(
    request_id
):

    conn = (
        get_db_connection()
    )


    conn.execute("""
        UPDATE shift_requests

        SET
            status = 'rejected'

        WHERE
            id = ?

            AND

            status = 'pending'
    """, (
        request_id,
    ))


    conn.commit()

    conn.close()


    flash(
        "申請を却下しました"
    )


    return redirect(
        "/requests"
    )


# ==================================================
# Dashboard
# ==================================================

@app.route(
    "/dashboard"
)
@login_required
def dashboard():

    today = date.today()


    selected_month = (
        request.args.get(
            "month"
        )
    )


    try:

        if (
            selected_month
        ):

            target_date = (
                datetime.strptime(
                    selected_month,
                    "%Y-%m"
                ).date()
            )

        else:

            target_date = today


    except ValueError:

        target_date = today


    month_start = (
        target_date.replace(
            day=1
        )
    )


    next_month_start = (

        month_start
        + timedelta(
            days=32
        )

    ).replace(
        day=1
    )


    month_end = (
        next_month_start
        - timedelta(
            days=1
        )
    )


    previous_month = (

        month_start
        - timedelta(
            days=1
        )

    ).replace(
        day=1
    )


    next_month = (
        next_month_start
    )


    month_start_text = (
        month_start.isoformat()
    )


    month_end_text = (
        month_end.isoformat()
    )


    alert_start = today


    alert_end = (
        today
        + timedelta(
            days=59
        )
    )


    conn = (
        get_db_connection()
    )


    # ==================================================
    # 员工人数
    # ==================================================

    total_staff = (
        conn.execute("""
            SELECT
                COUNT(*) AS count

            FROM staff
        """).fetchone()[
            "count"
        ]
    )


    # ==================================================
    # 月度班次数
    # ==================================================

    month_shift_count = (
        conn.execute("""
            SELECT
                COUNT(*) AS count

            FROM shifts

            WHERE
                shift_date >= ?

                AND

                shift_date <= ?
        """, (

            month_start_text,

            month_end_text

        )).fetchone()[
            "count"
        ]
    )


    # ==================================================
    # 自动生成数
    # ==================================================

    auto_shift_count = (
        conn.execute("""
            SELECT
                COUNT(*) AS count

            FROM shifts

            WHERE
                shift_date >= ?

                AND

                shift_date <= ?

                AND

                source = 'auto'
        """, (

            month_start_text,

            month_end_text

        )).fetchone()[
            "count"
        ]
    )


    # ==================================================
    # 待处理申请
    # ==================================================

    pending_request_count = (
        conn.execute("""
            SELECT
                COUNT(*) AS count

            FROM shift_requests

            WHERE
                status = 'pending'
        """).fetchone()[
            "count"
        ]
    )


    # ==================================================
    # 当前月份缺员
    # ==================================================

    month_requirements = (
        conn.execute("""
            SELECT
                work_date,

                start_time,

                end_time,

                required_staff

            FROM staffing_requirements

            WHERE
                work_date >= ?

                AND

                work_date <= ?

            ORDER BY
                work_date,
                start_time
        """, (

            month_start_text,

            month_end_text

        )).fetchall()
    )


    month_shortage_count = 0


    for requirement in (
        month_requirements
    ):


        assigned_count = (
            conn.execute("""
                SELECT
                    COUNT(
                        DISTINCT employee_id
                    ) AS count

                FROM shifts

                WHERE
                    shift_date = ?

                    AND

                    start_time <= ?

                    AND

                    end_time >= ?
            """, (

                requirement[
                    "work_date"
                ],

                requirement[
                    "start_time"
                ],

                requirement[
                    "end_time"
                ]

            )).fetchone()[
                "count"
            ]
        )


        shortage = (

            requirement[
                "required_staff"
            ]

            - assigned_count
        )


        if (
            shortage > 0
        ):

            month_shortage_count += (
                shortage
            )


    # ==================================================
    # 未来60天缺员
    # ==================================================

    future_requirements = (
        conn.execute("""
            SELECT
                work_date,

                start_time,

                end_time,

                required_staff

            FROM staffing_requirements

            WHERE
                work_date >= ?

                AND

                work_date <= ?

            ORDER BY
                work_date,
                start_time
        """, (

            alert_start.isoformat(),

            alert_end.isoformat()

        )).fetchall()
    )


    shortage_alerts = []


    for requirement in (
        future_requirements
    ):


        assigned_count = (
            conn.execute("""
                SELECT
                    COUNT(
                        DISTINCT employee_id
                    ) AS count

                FROM shifts

                WHERE
                    shift_date = ?

                    AND

                    start_time <= ?

                    AND

                    end_time >= ?
            """, (

                requirement[
                    "work_date"
                ],

                requirement[
                    "start_time"
                ],

                requirement[
                    "end_time"
                ]

            )).fetchone()[
                "count"
            ]
        )


        shortage = (

            requirement[
                "required_staff"
            ]

            - assigned_count
        )


        if (
            shortage > 0
        ):

            shortage_alerts.append({

                "work_date":
                    requirement[
                        "work_date"
                    ],

                "start_time":
                    requirement[
                        "start_time"
                    ],

                "end_time":
                    requirement[
                        "end_time"
                    ],

                "required_staff":
                    requirement[
                        "required_staff"
                    ],

                "assigned_staff":
                    assigned_count,

                "shortage":
                    shortage
            })


    future_shortage_count = sum(

        item[
            "shortage"
        ]

        for item
        in shortage_alerts
    )


    # ==================================================
    # 未来排班
    # ==================================================

    upcoming_shifts = (
        conn.execute("""
            SELECT
                staff.name,

                shifts.shift_date,

                shifts.start_time,

                shifts.end_time,

                shifts.source

            FROM shifts

            JOIN staff

            ON
                shifts.employee_id
                = staff.id

            WHERE
                shifts.shift_date >= ?

            ORDER BY
                shifts.shift_date,

                shifts.start_time,

                staff.name

            LIMIT 12
        """, (
            today.isoformat(),
        )).fetchall()
    )


    conn.close()


    return render_template(

        "dashboard.html",

        total_staff=(
            total_staff
        ),

        month_shift_count=(
            month_shift_count
        ),

        auto_shift_count=(
            auto_shift_count
        ),

        month_shortage_count=(
            month_shortage_count
        ),

        future_shortage_count=(
            future_shortage_count
        ),

        pending_request_count=(
            pending_request_count
        ),

        shortage_alerts=(
            shortage_alerts
        ),

        upcoming_shifts=(
            upcoming_shifts
        ),

        month_title=(
            month_start.strftime(
                "%Y年%m月"
            )
        ),

        previous_month=(
            previous_month.strftime(
                "%Y-%m"
            )
        ),

        next_month=(
            next_month.strftime(
                "%Y-%m"
            )
        ),

        alert_start=(
            alert_start.isoformat()
        ),

        alert_end=(
            alert_end.isoformat()
        )
    )


# ==================================================
# 排班管理
# ==================================================

@app.route(
    "/",
    methods=[
        "GET",
        "POST"
    ]
)
@login_required
def home():

    conn = (
        get_db_connection()
    )


    if (
        request.method
        == "POST"
    ):

        employee_id = (
            request.form[
                "employee_id"
            ]
        )


        shift_date = (
            request.form[
                "shift_date"
            ]
        )


        start_time = (
            request.form[
                "start_time"
            ]
        )


        end_time = (
            request.form[
                "end_time"
            ]
        )


        if (
            time_to_minutes(
                end_time
            )

            <=

            time_to_minutes(
                start_time
            )
        ):

            flash(
                "終了時間は開始時間より後に設定してください"
            )

            conn.close()

            return redirect(
                "/"
            )


        # ==================================================
        # 时间重叠检查
        # ==================================================

        conflict = (
            conn.execute("""
                SELECT
                    id

                FROM shifts

                WHERE
                    employee_id = ?

                    AND

                    shift_date = ?

                    AND

                    start_time < ?

                    AND

                    end_time > ?
            """, (

                employee_id,

                shift_date,

                end_time,

                start_time

            )).fetchone()
        )


        if (
            conflict is not None
        ):

            flash(
                "このスタッフは同じ時間帯にすでにシフトがあります"
            )

            conn.close()

            return redirect(
                "/"
            )


        conn.execute("""
            INSERT INTO shifts (

                employee_id,

                shift_date,

                start_time,

                end_time,

                source
            )

            VALUES (
                ?, ?, ?, ?, ?
            )
        """, (

            employee_id,

            shift_date,

            start_time,

            end_time,

            "manual"

        ))


        conn.commit()

        conn.close()


        return redirect(
            "/"
        )


    staff_list = (
        conn.execute("""
            SELECT
                id,
                name

            FROM staff

            ORDER BY
                name
        """).fetchall()
    )


    employees = (
        conn.execute("""
            SELECT
                shifts.id
                AS id,

                staff.name
                AS name,

                shifts.shift_date
                AS shift_date,

                shifts.start_time
                AS start_time,

                shifts.end_time
                AS end_time,

                shifts.source
                AS source

            FROM shifts

            JOIN staff

            ON
                shifts.employee_id
                = staff.id

            ORDER BY
                shifts.shift_date,

                shifts.start_time,

                staff.name
        """).fetchall()
    )


    conn.close()


    return render_template(

        "index.html",

        employees=employees,

        staff_list=staff_list
    )


# ==================================================
# 周排班
# ==================================================

@app.route(
    "/weekly"
)
@login_required
def weekly():

    selected_date = (
        request.args.get(
            "date"
        )
    )


    try:

        if (
            selected_date
        ):

            target_date = (
                datetime.strptime(
                    selected_date,
                    "%Y-%m-%d"
                ).date()
            )

        else:

            target_date = (
                date.today()
            )


    except ValueError:

        target_date = (
            date.today()
        )


    monday = (

        target_date

        - timedelta(
            days=(
                target_date.weekday()
            )
        )
    )


    week_dates = [

        monday
        + timedelta(
            days=i
        )

        for i
        in range(7)
    ]


    japanese_weekdays = [
        "月",
        "火",
        "水",
        "木",
        "金",
        "土",
        "日"
    ]


    week_days = []


    for (
        index,
        day
    ) in enumerate(
        week_dates
    ):

        week_days.append({

            "iso":
                day.isoformat(),

            "label":
                (
                    f"{day.month}/"
                    f"{day.day}"
                    f"（"
                    f"{japanese_weekdays[index]}"
                    f"）"
                )
        })


    start_date = (
        week_dates[
            0
        ].isoformat()
    )


    end_date = (
        week_dates[
            -1
        ].isoformat()
    )


    conn = (
        get_db_connection()
    )


    staff_list = (
        conn.execute("""
            SELECT
                id,
                name

            FROM staff

            ORDER BY
                id
        """).fetchall()
    )


    shift_list = (
        conn.execute("""
            SELECT
                id,

                employee_id,

                shift_date,

                start_time,

                end_time,

                source

            FROM shifts

            WHERE
                shift_date >= ?

                AND

                shift_date <= ?

            ORDER BY
                shift_date,
                start_time
        """, (

            start_date,

            end_date

        )).fetchall()
    )


    conn.close()


    schedule = {}


    for staff in (
        staff_list
    ):

        schedule[
            staff[
                "id"
            ]
        ] = {}


        for day in (
            week_days
        ):

            schedule[
                staff[
                    "id"
                ]
            ][
                day[
                    "iso"
                ]
            ] = []


    for shift in (
        shift_list
    ):

        employee_id = (
            shift[
                "employee_id"
            ]
        )


        shift_date = (
            shift[
                "shift_date"
            ]
        )


        if (
            employee_id
            in schedule

            and

            shift_date
            in schedule[
                employee_id
            ]
        ):

            schedule[
                employee_id
            ][
                shift_date
            ].append({

                "id":
                    shift[
                        "id"
                    ],

                "start_time":
                    shift[
                        "start_time"
                    ],

                "end_time":
                    shift[
                        "end_time"
                    ],

                "source":
                    shift[
                        "source"
                    ]
            })


    previous_week = (

        monday
        - timedelta(
            days=7
        )

    ).isoformat()


    next_week = (

        monday
        + timedelta(
            days=7
        )

    ).isoformat()


    return render_template(

        "weekly.html",

        staff_list=(
            staff_list
        ),

        week_days=(
            week_days
        ),

        schedule=(
            schedule
        ),

        start_date=(
            start_date
        ),

        end_date=(
            end_date
        ),

        previous_week=(
            previous_week
        ),

        next_week=(
            next_week
        )
    )


# ==================================================
# 自动排班
# ==================================================

@app.route(
    "/auto-generate",
    methods=[
        "POST"
    ]
)
@login_required
def auto_generate():

    conn = (
        get_db_connection()
    )


    requirements = (
        conn.execute("""
            SELECT
                work_date,

                start_time,

                end_time,

                required_staff

            FROM staffing_requirements

            ORDER BY
                work_date,
                start_time
        """).fetchall()
    )


    if (
        not requirements
    ):

        conn.close()

        flash(
            "必要人数が登録されていません。"
            "先に必要人数設定を行ってください。"
        )

        return redirect(
            "/"
        )


    generated_count = 0

    shortage_count = 0

    no_candidate_count = 0


    for requirement in (
        requirements
    ):


        work_date = (
            requirement[
                "work_date"
            ]
        )


        start_time = (
            requirement[
                "start_time"
            ]
        )


        end_time = (
            requirement[
                "end_time"
            ]
        )


        required_staff = (
            requirement[
                "required_staff"
            ]
        )


        duration = (

            time_to_minutes(
                end_time
            )

            -

            time_to_minutes(
                start_time
            )
        )


        if (
            duration <= 0

            or

            duration > 480
        ):

            continue


        existing_count = (
            conn.execute("""
                SELECT
                    COUNT(
                        DISTINCT employee_id
                    ) AS count

                FROM shifts

                WHERE
                    shift_date = ?

                    AND

                    start_time <= ?

                    AND

                    end_time >= ?
            """, (

                work_date,

                start_time,

                end_time

            )).fetchone()[
                "count"
            ]
        )


        needed = (

            required_staff

            - existing_count
        )


        if (
            needed <= 0
        ):

            continue


        candidates = (
            conn.execute("""
                SELECT
                    staff.id,

                    staff.name,

                    (
                        SELECT
                            COUNT(*)

                        FROM shifts
                        AS total_shifts

                        WHERE
                            total_shifts.employee_id
                            = staff.id

                    ) AS shift_count

                FROM staff

                JOIN availability

                ON
                    availability.employee_id
                    = staff.id

                WHERE
                    availability.work_date
                    = ?

                    AND

                    availability.preference_type
                    = 'available'

                    AND

                    availability.start_time
                    <= ?

                    AND

                    availability.end_time
                    >= ?

                    AND NOT EXISTS (

                        SELECT 1

                        FROM shifts
                        AS same_day_shift

                        WHERE
                            same_day_shift.employee_id
                            = staff.id

                            AND

                            same_day_shift.shift_date
                            = ?
                    )

                ORDER BY
                    shift_count ASC,

                    staff.id ASC
            """, (

                work_date,

                start_time,

                end_time,

                work_date

            )).fetchall()
        )


        if (
            not candidates
        ):

            no_candidate_count += 1

            shortage_count += (
                needed
            )

            continue


        selected = (
            candidates[
                :needed
            ]
        )


        for staff in (
            selected
        ):

            conn.execute("""
                INSERT INTO shifts (

                    employee_id,

                    shift_date,

                    start_time,

                    end_time,

                    source
                )

                VALUES (
                    ?, ?, ?, ?, ?
                )
            """, (

                staff[
                    "id"
                ],

                work_date,

                start_time,

                end_time,

                "auto"

            ))


            generated_count += 1


        if (
            len(selected)
            < needed
        ):

            shortage_count += (

                needed
                - len(selected)
            )


    conn.commit()

    conn.close()


    if (
        generated_count > 0
    ):

        if (
            shortage_count > 0
        ):

            flash(
                f"自動シフトを"
                f"{generated_count}件作成しました。"
                f"ただし、"
                f"{shortage_count}人分不足しています。"
            )

        else:

            flash(
                f"自動シフトを"
                f"{generated_count}件作成しました。"
            )


    elif (
        no_candidate_count > 0
    ):

        flash(
            "条件に合う勤務可能スタッフがいません。"
            "勤務希望を確認してください。"
        )


    else:

        flash(
            "必要人数はすでに満たされています。"
        )


    return redirect(
        "/"
    )


# ==================================================
# 自动排班清除
# ==================================================

@app.route(
    "/auto-clear",
    methods=[
        "POST"
    ]
)
@login_required
def auto_clear():

    conn = (
        get_db_connection()
    )


    deleted_count = (
        conn.execute("""
            SELECT
                COUNT(*) AS count

            FROM shifts

            WHERE
                source = 'auto'
        """).fetchone()[
            "count"
        ]
    )


    conn.execute("""
        DELETE FROM shifts

        WHERE
            source = 'auto'
    """)


    conn.commit()

    conn.close()


    flash(
        f"自動作成シフトを"
        f"{deleted_count}件削除しました"
    )


    return redirect(
        "/"
    )


# ==================================================
# 删除排班
# ==================================================

@app.route(
    "/delete/<int:shift_id>"
)
@login_required
def delete(
    shift_id
):

    conn = (
        get_db_connection()
    )


    conn.execute("""
        DELETE FROM shifts

        WHERE
            id = ?
    """, (
        shift_id,
    ))


    conn.commit()

    conn.close()


    return redirect(
        "/"
    )


# ==================================================
# 编辑排班
# ==================================================

@app.route(
    "/edit/<int:shift_id>",
    methods=[
        "GET",
        "POST"
    ]
)
@login_required
def edit(
    shift_id
):

    conn = (
        get_db_connection()
    )


    if (
        request.method
        == "POST"
    ):

        name = (
            request.form[
                "name"
            ]
        )


        shift_date = (
            request.form[
                "shift_date"
            ]
        )


        start_time = (
            request.form[
                "start_time"
            ]
        )


        end_time = (
            request.form[
                "end_time"
            ]
        )


        if (
            time_to_minutes(
                end_time
            )

            <=

            time_to_minutes(
                start_time
            )
        ):

            flash(
                "終了時間は開始時間より後に設定してください"
            )

            conn.close()

            return redirect(
                f"/edit/{shift_id}"
            )


        staff = (
            conn.execute("""
                SELECT
                    id

                FROM staff

                WHERE
                    name = ?
            """, (
                name,
            )).fetchone()
        )


        if (
            staff is None
        ):

            password_hash = (
                generate_password_hash(
                    "1234",
                    method="pbkdf2:sha256"
                )
            )


            cursor = (
                conn.execute("""
                    INSERT INTO staff (
                        name,
                        password_hash
                    )

                    VALUES (
                        ?, ?
                    )
                """, (

                    name,

                    password_hash

                ))
            )


            employee_id = (
                cursor.lastrowid
            )


        else:

            employee_id = (
                staff[
                    "id"
                ]
            )


        conn.execute("""
            UPDATE shifts

            SET
                employee_id = ?,

                shift_date = ?,

                start_time = ?,

                end_time = ?

            WHERE
                id = ?
        """, (

            employee_id,

            shift_date,

            start_time,

            end_time,

            shift_id

        ))


        conn.commit()

        conn.close()


        return redirect(
            "/"
        )


    emp = (
        conn.execute("""
            SELECT
                shifts.id
                AS id,

                staff.name
                AS name,

                shifts.shift_date
                AS shift_date,

                shifts.start_time
                AS start_time,

                shifts.end_time
                AS end_time

            FROM shifts

            JOIN staff

            ON
                shifts.employee_id
                = staff.id

            WHERE
                shifts.id = ?
        """, (
            shift_id,
        )).fetchone()
    )


    conn.close()


    if (
        emp is None
    ):

        return redirect(
            "/"
        )


    return render_template(
        "edit.html",
        emp=emp
    )


# ==================================================
# 员工管理
# ==================================================

@app.route(
    "/staff",
    methods=[
        "GET",
        "POST"
    ]
)
@login_required
def staff_management():

    conn = (
        get_db_connection()
    )


    if (
        request.method
        == "POST"
    ):

        name = (
            request.form[
                "name"
            ].strip()
        )


        if (
            name
        ):

            existing_staff = (
                conn.execute("""
                    SELECT
                        id

                    FROM staff

                    WHERE
                        name = ?
                """, (
                    name,
                )).fetchone()
            )


            if (
                existing_staff
                is None
            ):

                password_hash = (
                    generate_password_hash(
                        "1234",
                        method="pbkdf2:sha256"
                    )
                )


                conn.execute("""
                    INSERT INTO staff (
                        name,
                        password_hash
                    )

                    VALUES (
                        ?, ?
                    )
                """, (

                    name,

                    password_hash

                ))


                conn.commit()


                flash(
                    "スタッフを追加しました。"
                    "初期PINは1234です。"
                )


            else:

                flash(
                    "同じ名前のスタッフが既に登録されています"
                )


        conn.close()


        return redirect(
            "/staff"
        )


    staff_list = (
        conn.execute("""
            SELECT
                staff.id,

                staff.name,

                (
                    SELECT
                        COUNT(*)

                    FROM shifts

                    WHERE
                        shifts.employee_id
                        = staff.id

                ) AS shift_count,

                (
                    SELECT
                        COUNT(*)

                    FROM availability

                    WHERE
                        availability.employee_id
                        = staff.id

                ) AS availability_count

            FROM staff

            ORDER BY
                staff.id
        """).fetchall()
    )


    conn.close()


    return render_template(

        "staff.html",

        staff_list=(
            staff_list
        )
    )


# ==================================================
# 删除员工
# ==================================================

@app.route(
    "/staff/delete/<int:staff_id>"
)
@login_required
def delete_staff(
    staff_id
):

    conn = (
        get_db_connection()
    )


    shift_count = (
        conn.execute("""
            SELECT
                COUNT(*) AS count

            FROM shifts

            WHERE
                employee_id = ?
        """, (
            staff_id,
        )).fetchone()[
            "count"
        ]
    )


    availability_count = (
        conn.execute("""
            SELECT
                COUNT(*) AS count

            FROM availability

            WHERE
                employee_id = ?
        """, (
            staff_id,
        )).fetchone()[
            "count"
        ]
    )


    if (
        shift_count > 0

        or

        availability_count > 0
    ):

        flash(
            "シフトまたは勤務希望が登録されているスタッフは削除できません"
        )

        conn.close()

        return redirect(
            "/staff"
        )


    conn.execute("""
        DELETE FROM staff

        WHERE
            id = ?
    """, (
        staff_id,
    ))


    conn.commit()

    conn.close()


    flash(
        "スタッフを削除しました"
    )


    return redirect(
        "/staff"
    )


# ==================================================
# 勤務希望
# ==================================================

@app.route(
    "/availability/<int:staff_id>",
    methods=[
        "GET",
        "POST"
    ]
)
@login_required
def availability(
    staff_id
):

    conn = (
        get_db_connection()
    )


    staff = (
        conn.execute("""
            SELECT
                id,
                name

            FROM staff

            WHERE
                id = ?
        """, (
            staff_id,
        )).fetchone()
    )


    if (
        staff is None
    ):

        conn.close()

        return redirect(
            "/staff"
        )


    if (
        request.method
        == "POST"
    ):

        work_date = (
            request.form[
                "work_date"
            ]
        )


        preference_type = (
            request.form[
                "preference_type"
            ]
        )


        start_time = (
            request.form.get(
                "start_time",
                ""
            )
        )


        end_time = (
            request.form.get(
                "end_time",
                ""
            )
        )


        if (
            preference_type
            == "off"
        ):

            start_time = None

            end_time = None


        else:

            if (
                not start_time

                or

                not end_time
            ):

                flash(
                    "勤務可能の場合は開始時間と終了時間を入力してください"
                )

                conn.close()

                return redirect(
                    f"/availability/{staff_id}"
                )


            if (
                time_to_minutes(
                    end_time
                )

                <=

                time_to_minutes(
                    start_time
                )
            ):

                flash(
                    "終了時間は開始時間より後に設定してください"
                )

                conn.close()

                return redirect(
                    f"/availability/{staff_id}"
                )


        conn.execute("""
            INSERT INTO availability (

                employee_id,

                work_date,

                preference_type,

                start_time,

                end_time
            )

            VALUES (
                ?, ?, ?, ?, ?
            )

            ON CONFLICT (
                employee_id,
                work_date
            )

            DO UPDATE SET

                preference_type =
                    excluded.preference_type,

                start_time =
                    excluded.start_time,

                end_time =
                    excluded.end_time
        """, (

            staff_id,

            work_date,

            preference_type,

            start_time,

            end_time

        ))


        conn.commit()

        conn.close()


        flash(
            "勤務希望を保存しました"
        )


        return redirect(
            f"/availability/{staff_id}"
        )


    availability_list = (
        conn.execute("""
            SELECT
                id,

                work_date,

                preference_type,

                start_time,

                end_time

            FROM availability

            WHERE
                employee_id = ?

            ORDER BY
                work_date
        """, (
            staff_id,
        )).fetchall()
    )


    conn.close()


    return render_template(

        "availability.html",

        staff=staff,

        availability_list=(
            availability_list
        )
    )


# ==================================================
# 删除勤務希望
# ==================================================

@app.route(
    "/availability/delete/<int:availability_id>"
)
@login_required
def delete_availability(
    availability_id
):

    conn = (
        get_db_connection()
    )


    record = (
        conn.execute("""
            SELECT
                employee_id

            FROM availability

            WHERE
                id = ?
        """, (
            availability_id,
        )).fetchone()
    )


    if (
        record is None
    ):

        conn.close()

        return redirect(
            "/staff"
        )


    staff_id = (
        record[
            "employee_id"
        ]
    )


    conn.execute("""
        DELETE FROM availability

        WHERE
            id = ?
    """, (
        availability_id,
    ))


    conn.commit()

    conn.close()


    return redirect(
        f"/availability/{staff_id}"
    )


# ==================================================
# 必要人数设置
# ==================================================

@app.route(
    "/requirements",
    methods=[
        "GET",
        "POST"
    ]
)
@login_required
def requirements():

    conn = (
        get_db_connection()
    )


    if (
        request.method
        == "POST"
    ):

        work_date = (
            request.form[
                "work_date"
            ]
        )


        start_time = (
            request.form[
                "start_time"
            ]
        )


        end_time = (
            request.form[
                "end_time"
            ]
        )


        required_staff = int(
            request.form[
                "required_staff"
            ]
        )


        duration = (

            time_to_minutes(
                end_time
            )

            -

            time_to_minutes(
                start_time
            )
        )


        if (
            duration <= 0
        ):

            flash(
                "終了時間は開始時間より後に設定してください"
            )

            conn.close()

            return redirect(
                "/requirements"
            )


        if (
            duration > 480
        ):

            flash(
                "1つの必要時間帯は8時間以内に設定してください"
            )

            conn.close()

            return redirect(
                "/requirements"
            )


        if (
            required_staff < 1
        ):

            flash(
                "必要人数は1人以上に設定してください"
            )

            conn.close()

            return redirect(
                "/requirements"
            )


        conn.execute("""
            INSERT INTO staffing_requirements (

                work_date,

                start_time,

                end_time,

                required_staff
            )

            VALUES (
                ?, ?, ?, ?
            )

            ON CONFLICT (
                work_date,
                start_time,
                end_time
            )

            DO UPDATE SET

                required_staff =
                    excluded.required_staff
        """, (

            work_date,

            start_time,

            end_time,

            required_staff

        ))


        conn.commit()

        conn.close()


        flash(
            "必要人数を保存しました"
        )


        return redirect(
            "/requirements"
        )


    requirement_list = (
        conn.execute("""
            SELECT
                id,

                work_date,

                start_time,

                end_time,

                required_staff

            FROM staffing_requirements

            ORDER BY
                work_date,
                start_time
        """).fetchall()
    )


    conn.close()


    return render_template(

        "requirements.html",

        requirement_list=(
            requirement_list
        )
    )


# ==================================================
# 删除必要人数
# ==================================================

@app.route(
    "/requirements/delete/<int:requirement_id>"
)
@login_required
def delete_requirement(
    requirement_id
):

    conn = (
        get_db_connection()
    )


    conn.execute("""
        DELETE FROM staffing_requirements

        WHERE
            id = ?
    """, (
        requirement_id,
    ))


    conn.commit()

    conn.close()


    return redirect(
        "/requirements"
    )


# ==================================================
# 启动
# ==================================================

if __name__ == "__main__":

    init_db()

    app.run(
        debug=True,
        port=5001
    )