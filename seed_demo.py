import sqlite3

from datetime import datetime

from werkzeug.security import (
    generate_password_hash
)


DB_PATH = "shift.db"


def main():

    conn = sqlite3.connect(DB_PATH)

    conn.execute(
        "PRAGMA foreign_keys = ON"
    )

    cursor = conn.cursor()


    # ==========================================
    # 1. 清理所有测试数据
    # ==========================================

    cursor.execute(
        "DELETE FROM shift_requests"
    )

    cursor.execute(
        "DELETE FROM shifts"
    )

    cursor.execute(
        "DELETE FROM availability"
    )

    cursor.execute(
        "DELETE FROM staffing_requirements"
    )

    cursor.execute(
        "DELETE FROM staff"
    )


    # 重置ID
    cursor.execute(
        """
        DELETE FROM sqlite_sequence
        WHERE name IN (
            'shift_requests',
            'shifts',
            'availability',
            'staffing_requirements',
            'staff'
        )
        """
    )


    # ==========================================
    # 2. 创建演示员工
    # ==========================================

    default_password = (
        generate_password_hash(
            "1234",
            method="pbkdf2:sha256"
        )
    )


    staff_names = [
        "田中",
        "井上",
        "佐藤",
        "小林",
        "鈴木",
        "山田"
    ]


    staff_ids = {}


    for name in staff_names:

        cursor.execute(
            """
            INSERT INTO staff (
                name,
                password_hash
            )

            VALUES (?, ?)
            """,
            (
                name,
                default_password
            )
        )

        staff_ids[name] = (
            cursor.lastrowid
        )


    # ==========================================
    # 3. 必要人数
    # ==========================================

    requirements = [

        (
            "2026-10-12",
            "09:00",
            "17:00",
            2
        ),

        (
            "2026-10-18",
            "07:00",
            "15:00",
            3
        ),

        (
            "2026-10-24",
            "09:00",
            "17:00",
            4
        )
    ]


    cursor.executemany(
        """
        INSERT INTO staffing_requirements (
            work_date,
            start_time,
            end_time,
            required_staff
        )

        VALUES (?, ?, ?, ?)
        """,
        requirements
    )


    # ==========================================
    # 4. 10月12日勤務希望
    # ==========================================

    availability_data = [

        (
            staff_ids["田中"],
            "2026-10-12",
            "available",
            "09:00",
            "17:00"
        ),

        (
            staff_ids["井上"],
            "2026-10-12",
            "available",
            "09:00",
            "17:00"
        ),

        (
            staff_ids["山田"],
            "2026-10-12",
            "off",
            None,
            None
        ),


        # ======================================
        # 10月18日
        # ======================================

        (
            staff_ids["田中"],
            "2026-10-18",
            "available",
            "07:00",
            "15:00"
        ),

        (
            staff_ids["佐藤"],
            "2026-10-18",
            "available",
            "07:00",
            "15:00"
        ),

        (
            staff_ids["小林"],
            "2026-10-18",
            "available",
            "07:00",
            "15:00"
        ),

        (
            staff_ids["鈴木"],
            "2026-10-18",
            "available",
            "07:00",
            "12:00"
        ),

        (
            staff_ids["山田"],
            "2026-10-18",
            "available",
            "07:00",
            "15:00"
        ),


        # ======================================
        # 10月24日
        # 故意只准备3个人，制造1人不足
        # ======================================

        (
            staff_ids["佐藤"],
            "2026-10-24",
            "available",
            "09:00",
            "17:00"
        ),

        (
            staff_ids["鈴木"],
            "2026-10-24",
            "available",
            "09:00",
            "17:00"
        ),

        (
            staff_ids["山田"],
            "2026-10-24",
            "available",
            "09:00",
            "17:00"
        )
    ]


    cursor.executemany(
        """
        INSERT INTO availability (
            employee_id,
            work_date,
            preference_type,
            start_time,
            end_time
        )

        VALUES (?, ?, ?, ?, ?)
        """,
        availability_data
    )


    # ==========================================
    # 5. 10月12日排班
    # ==========================================

    cursor.execute(
        """
        INSERT INTO shifts (
            employee_id,
            shift_date,
            start_time,
            end_time,
            source
        )

        VALUES (?, ?, ?, ?, ?)
        """,
        (
            staff_ids["田中"],
            "2026-10-12",
            "09:00",
            "17:00",
            "auto"
        )
    )


    cursor.execute(
        """
        INSERT INTO shifts (
            employee_id,
            shift_date,
            start_time,
            end_time,
            source
        )

        VALUES (?, ?, ?, ?, ?)
        """,
        (
            staff_ids["井上"],
            "2026-10-12",
            "09:00",
            "17:00",
            "auto"
        )
    )


    # ==========================================
    # 6. 10月18日排班
    # ==========================================

    # 田中：后面用来演示休假申请

    cursor.execute(
        """
        INSERT INTO shifts (
            employee_id,
            shift_date,
            start_time,
            end_time,
            source
        )

        VALUES (?, ?, ?, ?, ?)
        """,
        (
            staff_ids["田中"],
            "2026-10-18",
            "07:00",
            "15:00",
            "manual"
        )
    )

    tanaka_shift_id = (
        cursor.lastrowid
    )


    cursor.execute(
        """
        INSERT INTO shifts (
            employee_id,
            shift_date,
            start_time,
            end_time,
            source
        )

        VALUES (?, ?, ?, ?, ?)
        """,
        (
            staff_ids["佐藤"],
            "2026-10-18",
            "07:00",
            "15:00",
            "auto"
        )
    )


    cursor.execute(
        """
        INSERT INTO shifts (
            employee_id,
            shift_date,
            start_time,
            end_time,
            source
        )

        VALUES (?, ?, ?, ?, ?)
        """,
        (
            staff_ids["小林"],
            "2026-10-18",
            "07:00",
            "15:00",
            "auto"
        )
    )


    # ==========================================
    # 7. 10月24日
    # 故意缺1人，用于Dashboard预警
    # ==========================================

    for name in [
        "佐藤",
        "鈴木",
        "山田"
    ]:

        cursor.execute(
            """
            INSERT INTO shifts (
                employee_id,
                shift_date,
                start_time,
                end_time,
                source
            )

            VALUES (?, ?, ?, ?, ?)
            """,
            (
                staff_ids[name],
                "2026-10-24",
                "09:00",
                "17:00",
                "auto"
            )
        )


    # ==========================================
    # 8. 创建一条正式演示用休假申请
    # ==========================================

    cursor.execute(
        """
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
            ?, ?
        )
        """,
        (
            staff_ids["田中"],
            tanaka_shift_id,
            "2026-10-18",
            "07:00",
            "15:00",
            "leave",
            None,
            None,
            "大学の試験のため",
            "pending",
            datetime.now().strftime(
                "%Y-%m-%d %H:%M"
            )
        )
    )


    conn.commit()
    conn.close()


    print("")
    print("==============================")
    print("演示数据创建完成")
    print("==============================")
    print("")
    print("管理者：")
    print("admin / 123456")
    print("")
    print("スタッフ：")
    print("ID 1 田中 / PIN 1234")
    print("ID 2 井上 / PIN 1234")
    print("ID 3 佐藤 / PIN 1234")
    print("ID 4 小林 / PIN 1234")
    print("ID 5 鈴木 / PIN 1234")
    print("ID 6 山田 / PIN 1234")
    print("")


if __name__ == "__main__":

    main()