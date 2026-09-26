from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
import secrets
import time
from functools import wraps

app = Flask(__name__)
app.secret_key = "stocksense-secret-key-change-this-later"


# =========================================================
# DATABASE CONNECTION
# =========================================================

def connect_database():
    return mysql.connector.connect(
        host="localhost",
        user="stocksense_user",
        password="StockSense@123",
        database="stocksense"
    )


# =========================================================
# LOGIN REQUIRED
# =========================================================

def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("logged_in"):
            flash("Please login to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Please enter email and password.", "error")
            return render_template("login.html")

        conn = None
        cursor = None

        try:
            conn = connect_database()
            cursor = conn.cursor(dictionary=True)

            cursor.execute(
                """
                SELECT id, name, email, password_hash, role
                FROM users
                WHERE email = %s
                """,
                (email,)
            )

            user = cursor.fetchone()

            if user and check_password_hash(user["password_hash"], password):

                session.clear()

                session["logged_in"] = True
                session["user_id"] = user["id"]
                session["user_name"] = user["name"]
                session["user_email"] = user["email"]
                session["user_role"] = user["role"]

                flash("Login successful.", "success")

                return redirect(url_for("dashboard"))

            flash("Invalid email or password.", "error")

        except mysql.connector.Error as e:
            flash(f"Database error: {e}", "error")

        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    return render_template("login.html")


# =========================================================
# SIGNUP
# =========================================================

@app.route("/signup", methods=["GET", "POST"])
def signup():

    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not name or not email or not password or not confirm_password:
            flash("All fields are required.", "error")
            return render_template("signup.html")

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("signup.html")

        if len(password) < 6:
            flash("Password must contain at least 6 characters.", "error")
            return render_template("signup.html")

        conn = None
        cursor = None

        try:
            conn = connect_database()
            cursor = conn.cursor(dictionary=True)

            cursor.execute(
                "SELECT id FROM users WHERE email = %s",
                (email,)
            )

            existing_user = cursor.fetchone()

            if existing_user:
                flash("An account with this email already exists.", "error")
                return render_template("signup.html")

            password_hash = generate_password_hash(password)

            cursor.execute(
                """
                INSERT INTO users
                (name, email, password_hash, role)
                VALUES (%s, %s, %s, %s)
                """,
                (
                    name,
                    email,
                    password_hash,
                    "Inventory Manager"
                )
            )

            conn.commit()

            flash("Account created successfully. Please login.", "success")

            return redirect(url_for("login"))

        except mysql.connector.Error as e:

            if conn:
                conn.rollback()

            flash(f"Database error: {e}", "error")

        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    return render_template("signup.html")


# =========================================================
# FORGOT PASSWORD
# =========================================================

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()

        if not email:
            flash("Please enter your email address.", "error")
            return render_template("forgot_password.html")

        conn = None
        cursor = None

        try:
            conn = connect_database()
            cursor = conn.cursor(dictionary=True)

            cursor.execute(
                "SELECT id, email FROM users WHERE email = %s",
                (email,)
            )

            user = cursor.fetchone()

            if not user:
                flash("No account was found with this email address.", "error")
                return render_template("forgot_password.html")

            # Generate 6 digit OTP
            otp = str(secrets.randbelow(900000) + 100000)

            # OTP valid for 5 minutes
            expiry = time.time() + 300

            session["reset_email"] = email
            session["reset_otp"] = otp
            session["reset_otp_expires"] = expiry
            session["otp_verified"] = False

            # Local/demo OTP
            session["demo_otp"] = otp

            return redirect(url_for("verify_otp"))

        except mysql.connector.Error as e:

            flash(f"Database error: {e}", "error")

        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    return render_template("forgot_password.html")


# =========================================================
# VERIFY OTP
# =========================================================

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():

    if "reset_email" not in session:
        flash("Please request a password reset first.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":

        entered_otp = request.form.get("otp", "").strip()

        saved_otp = session.get("reset_otp")
        expiry = session.get("reset_otp_expires")

        if not saved_otp or not expiry:
            flash("OTP session expired. Please request a new OTP.", "error")
            return redirect(url_for("forgot_password"))

        if time.time() > expiry:
            session.pop("reset_otp", None)
            session.pop("reset_otp_expires", None)
            session.pop("demo_otp", None)

            flash("OTP expired. Please request a new OTP.", "error")
            return redirect(url_for("forgot_password"))

        if entered_otp != saved_otp:
            flash("Invalid OTP. Please try again.", "error")
            return render_template(
                "verify_otp.html",
                demo_otp=session.get("demo_otp")
            )

        session["otp_verified"] = True

        session.pop("reset_otp", None)
        session.pop("reset_otp_expires", None)
        session.pop("demo_otp", None)

        return redirect(url_for("reset_password"))

    return render_template(
        "verify_otp.html",
        demo_otp=session.get("demo_otp")
    )


# =========================================================
# RESET PASSWORD
# =========================================================

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():

    if not session.get("otp_verified"):
        flash("Please verify the OTP first.", "error")
        return redirect(url_for("forgot_password"))

    email = session.get("reset_email")

    if not email:
        flash("Password reset session expired.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":

        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not password or not confirm_password:
            flash("Please enter both password fields.", "error")
            return render_template("reset_password.html")

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("reset_password.html")

        if len(password) < 6:
            flash("Password must contain at least 6 characters.", "error")
            return render_template("reset_password.html")

        password_hash = generate_password_hash(password)

        conn = None
        cursor = None

        try:
            conn = connect_database()
            cursor = conn.cursor()

            cursor.execute(
                """
                UPDATE users
                SET password_hash = %s
                WHERE email = %s
                """,
                (
                    password_hash,
                    email
                )
            )

            conn.commit()

            session.pop("reset_email", None)
            session.pop("otp_verified", None)

            flash(
                "Password reset successfully. Please login.",
                "success"
            )

            return redirect(url_for("login"))

        except mysql.connector.Error as e:

            if conn:
                conn.rollback()

            flash(f"Database error: {e}", "error")

        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    return render_template("reset_password.html")


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    flash("You have been logged out.", "success")

    return redirect(url_for("login"))


# =========================================================
# HELPER - GET WAREHOUSES
# =========================================================

def get_warehouses():

    conn = None
    cursor = None

    try:
        conn = connect_database()
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, name, code, address, status
            FROM warehouses
            ORDER BY name
            """
        )

        return cursor.fetchall()

    except mysql.connector.Error:
        return []

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


# =========================================================
# HELPER - ADD STOCK LEDGER ENTRY
# =========================================================

def add_ledger_entry(
    cursor,
    product_id,
    transaction_type,
    quantity,
    previous_stock,
    new_stock,
    reference_id=None
):

    cursor.execute(
        """
        INSERT INTO stock_ledger
        (
            product_id,
            transaction_type,
            quantity,
            previous_stock,
            new_stock,
            reference_id
        )
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (
            product_id,
            transaction_type,
            quantity,
            previous_stock,
            new_stock,
            reference_id
        )
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard():

    conn = None
    cursor = None

    try:

        conn = connect_database()
        cursor = conn.cursor(dictionary=True)

        # Total products
        cursor.execute(
            "SELECT COUNT(*) AS total FROM products"
        )
        total_products = cursor.fetchone()["total"]

        # Low stock
        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM products
            WHERE stock <= reorder_level
            """
        )
        low_stock = cursor.fetchone()["total"]

        # Pending receipts
        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM receipts
            WHERE status IN ('Waiting', 'Draft', 'Ready')
            """
        )
        pending_receipts = cursor.fetchone()["total"]

        # Pending deliveries
        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM deliveries
            WHERE status IN ('Waiting', 'Draft', 'Ready')
            """
        )
        pending_deliveries = cursor.fetchone()["total"]

        # Pending transfers
        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM transfers
            WHERE status IN ('Waiting', 'Draft', 'Ready')
            """
        )
        pending_transfers = cursor.fetchone()["total"]

        # Recent ledger activity
        cursor.execute(
            """
            SELECT
                sl.id,
                sl.transaction_type,
                sl.quantity,
                sl.previous_stock,
                sl.new_stock,
                sl.created_at,
                p.name AS product_name,
                p.sku
            FROM stock_ledger sl
            JOIN products p
                ON sl.product_id = p.id
            ORDER BY sl.created_at DESC
            LIMIT 10
            """
        )

        recent_activity = cursor.fetchall()

        # Alerts
        cursor.execute(
            """
            SELECT
                id,
                name,
                sku,
                stock,
                reorder_level
            FROM products
            WHERE stock <= reorder_level
            ORDER BY stock ASC
            LIMIT 10
            """
        )

        alerts = cursor.fetchall()

        return render_template(
            "dashboard.html",
            total_products=total_products,
            low_stock=low_stock,
            pending_receipts=pending_receipts,
            pending_deliveries=pending_deliveries,
            pending_transfers=pending_transfers,
            recent_activity=recent_activity,
            alerts=alerts
        )

    except mysql.connector.Error as e:

        flash(f"Database error: {e}", "error")

        return render_template(
            "dashboard.html",
            total_products=0,
            low_stock=0,
            pending_receipts=0,
            pending_deliveries=0,
            pending_transfers=0,
            recent_activity=[],
            alerts=[]
        )

    finally:
        if cursor:
            cursor.close()

        if conn:
            conn.close()


# =========================================================
# PRODUCTS
# =========================================================

@app.route("/products", methods=["GET", "POST"])
@login_required
def products():

    conn = None
    cursor = None

    try:

        conn = connect_database()
        cursor = conn.cursor(dictionary=True)

        if request.method == "POST":

            name = request.form.get("name", "").strip()
            sku = request.form.get("sku", "").strip()
            category = request.form.get("category", "").strip()
            unit = request.form.get("unit", "").strip()

            stock_value = request.form.get("stock", "0").strip()
            reorder_level_value = request.form.get(
                "reorder_level",
                "10"
            ).strip()

            if not name or not sku or not category or not unit:
                flash("Please fill all required product fields.", "error")
                return redirect(url_for("products"))

            try:
                stock = float(stock_value or 0)
                reorder_level = float(reorder_level_value or 10)
            except ValueError:
                flash("Stock and reorder level must be numbers.", "error")
                return redirect(url_for("products"))

            cursor.execute(
                "SELECT id FROM products WHERE sku = %s",
                (sku,)
            )

            existing = cursor.fetchone()

            if existing:
                flash("SKU already exists.", "error")
                return redirect(url_for("products"))

            cursor.execute(
                """
                INSERT INTO products
                (
                    name,
                    sku,
                    category,
                    unit,
                    stock,
                    reorder_level
                )
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    name,
                    sku,
                    category,
                    unit,
                    stock,
                    reorder_level
                )
            )

            product_id = cursor.lastrowid

            # Add initial stock to main warehouse
            cursor.execute(
                """
                SELECT id
                FROM warehouses
                WHERE status = 'Active'
                ORDER BY id
                LIMIT 1
                """
            )

            warehouse = cursor.fetchone()

            if warehouse and stock != 0:

                cursor.execute(
                    """
                    INSERT INTO product_stock
                    (
                        product_id,
                        warehouse_id,
                        quantity
                    )
                    VALUES (%s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                    quantity = quantity + VALUES(quantity)
                    """,
                    (
                        product_id,
                        warehouse["id"],
                        stock
                    )
                )

            if stock != 0:

                add_ledger_entry(
                    cursor,
                    product_id,
                    "Initial Stock",
                    stock,
                    0,
                    stock
                )

            conn.commit()

            flash("Product added successfully.", "success")

            return redirect(url_for("products"))

        # Get products
        cursor.execute(
            """
            SELECT
                id,
                name,
                sku,
                category,
                unit,
                stock,
                reorder_level,
                created_at
            FROM products
            ORDER BY id DESC
            """
        )

        product_list = cursor.fetchall()

        # Get warehouse stock
        cursor.execute(
            """
            SELECT
                ps.product_id,
                w.name AS warehouse_name,
                w.code AS warehouse_code,
                ps.quantity
            FROM product_stock ps
            JOIN warehouses w
                ON ps.warehouse_id = w.id
            ORDER BY w.name
            """
        )

        warehouse_stock_rows = cursor.fetchall()

        warehouse_stock_map = {}

        for row in warehouse_stock_rows:

            product_id = row["product_id"]

            if product_id not in warehouse_stock_map:
                warehouse_stock_map[product_id] = []

            warehouse_stock_map[product_id].append(row)

        for product in product_list:

            product["warehouse_stock"] = warehouse_stock_map.get(
                product["id"],
                []
            )

        warehouses = get_warehouses()

        return render_template(
            "products.html",
            products=product_list,
            warehouses=warehouses
        )

    except mysql.connector.Error as e:

        if conn:
            conn.rollback()

        flash(f"Database error: {e}", "error")

        return redirect(url_for("products"))

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# =========================================================
# RECEIPTS
# =========================================================

@app.route("/receipts", methods=["GET", "POST"])
@login_required
def receipts():

    conn = None
    cursor = None

    try:

        conn = connect_database()
        cursor = conn.cursor(dictionary=True)

        if request.method == "POST":

            supplier = request.form.get("supplier", "").strip()
            product_id = request.form.get("product_id", "").strip()
            warehouse_id = request.form.get("warehouse_id", "").strip()
            quantity_value = request.form.get("quantity", "").strip()

            if not supplier or not product_id or not quantity_value:
                flash("Please fill all required receipt fields.", "error")
                return redirect(url_for("receipts"))

            try:
                quantity = float(quantity_value)
            except ValueError:
                flash("Quantity must be a number.", "error")
                return redirect(url_for("receipts"))

            if quantity <= 0:
                flash("Quantity must be greater than zero.", "error")
                return redirect(url_for("receipts"))

            receipt_number = "REC-" + secrets.token_hex(4).upper()

            cursor.execute(
                """
                INSERT INTO receipts
                (
                    receipt_number,
                    supplier,
                    product_id,
                    warehouse_id,
                    quantity,
                    status
                )
                VALUES (%s, %s, %s, %s, %s, 'Waiting')
                """,
                (
                    receipt_number,
                    supplier,
                    product_id,
                    warehouse_id if warehouse_id else None,
                    quantity
                )
            )

            conn.commit()

            flash(
                f"Receipt {receipt_number} created successfully.",
                "success"
            )

            return redirect(url_for("receipts"))

        cursor.execute(
            """
            SELECT
                r.id,
                r.receipt_number,
                r.supplier,
                r.quantity,
                r.status,
                r.created_at,
                p.name AS product_name,
                p.sku,
                w.name AS warehouse_name,
                w.code AS warehouse_code
            FROM receipts r
            JOIN products p
                ON r.product_id = p.id
            LEFT JOIN warehouses w
                ON r.warehouse_id = w.id
            ORDER BY r.id DESC
            """
        )

        receipt_list = cursor.fetchall()

        cursor.execute(
            """
            SELECT
                id,
                name,
                sku,
                stock
            FROM products
            ORDER BY name
            """
        )

        product_list = cursor.fetchall()

        warehouses = get_warehouses()

        return render_template(
            "receipts.html",
            receipts=receipt_list,
            products=product_list,
            warehouses=warehouses
        )

    except mysql.connector.Error as e:

        if conn:
            conn.rollback()

        flash(f"Database error: {e}", "error")

        return redirect(url_for("receipts"))

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# =========================================================
# VALIDATE RECEIPT
# =========================================================

@app.route("/receipts/validate/<int:receipt_id>")
@login_required
def validate_receipt(receipt_id):

    conn = None
    cursor = None

    try:

        conn = connect_database()
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT *
            FROM receipts
            WHERE id = %s
            """,
            (receipt_id,)
        )

        receipt = cursor.fetchone()

        if not receipt:
            flash("Receipt not found.", "error")
            return redirect(url_for("receipts"))

        if receipt["status"] == "Done":
            flash("Receipt is already validated.", "error")
            return redirect(url_for("receipts"))

        product_id = receipt["product_id"]
        warehouse_id = receipt["warehouse_id"]
        quantity = float(receipt["quantity"])

        # Current product stock
        cursor.execute(
            """
            SELECT stock
            FROM products
            WHERE id = %s
            FOR UPDATE
            """,
            (product_id,)
        )

        product = cursor.fetchone()

        if not product:
            flash("Product not found.", "error")
            return redirect(url_for("receipts"))

        previous_stock = float(product["stock"])
        new_stock = previous_stock + quantity

        # Update total product stock
        cursor.execute(
            """
            UPDATE products
            SET stock = %s
            WHERE id = %s
            """,
            (
                new_stock,
                product_id
            )
        )

        # Update warehouse stock if warehouse selected
        if warehouse_id:

            cursor.execute(
                """
                INSERT INTO product_stock
                (
                    product_id,
                    warehouse_id,
                    quantity
                )
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE
                quantity = quantity + VALUES(quantity)
                """,
                (
                    product_id,
                    warehouse_id,
                    quantity
                )
            )

        add_ledger_entry(
            cursor,
            product_id,
            "Receipt",
            quantity,
            previous_stock,
            new_stock,
            receipt_id
        )

        cursor.execute(
            """
            UPDATE receipts
            SET status = 'Done'
            WHERE id = %s
            """,
            (receipt_id,)
        )

        conn.commit()

        flash(
            "Receipt validated and stock updated successfully.",
            "success"
        )

    except mysql.connector.Error as e:

        if conn:
            conn.rollback()

        flash(f"Database error: {e}", "error")

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()

    return redirect(url_for("receipts"))


# =========================================================
# DELIVERIES
# =========================================================

@app.route("/deliveries", methods=["GET", "POST"])
@login_required
def deliveries():

    conn = None
    cursor = None

    try:

        conn = connect_database()
        cursor = conn.cursor(dictionary=True)

        if request.method == "POST":

            customer = request.form.get("customer", "").strip()
            product_id = request.form.get("product_id", "").strip()
            quantity_value = request.form.get("quantity", "").strip()

            if not customer or not product_id or not quantity_value:
                flash("Please fill all required delivery fields.", "error")
                return redirect(url_for("deliveries"))

            try:
                quantity = float(quantity_value)
            except ValueError:
                flash("Quantity must be a number.", "error")
                return redirect(url_for("deliveries"))

            if quantity <= 0:
                flash("Quantity must be greater than zero.", "error")
                return redirect(url_for("deliveries"))

            delivery_number = "DEL-" + secrets.token_hex(4).upper()

            cursor.execute(
                """
                INSERT INTO deliveries
                (
                    delivery_number,
                    customer,
                    product_id,
                    quantity,
                    status
                )
                VALUES (%s, %s, %s, %s, 'Waiting')
                """,
                (
                    delivery_number,
                    customer,
                    product_id,
                    quantity
                )
            )

            conn.commit()

            flash(
                f"Delivery {delivery_number} created successfully.",
                "success"
            )

            return redirect(url_for("deliveries"))

        cursor.execute(
            """
            SELECT
                d.id,
                d.delivery_number,
                d.customer,
                d.quantity,
                d.status,
                d.created_at,
                p.name AS product_name,
                p.sku
            FROM deliveries d
            JOIN products p
                ON d.product_id = p.id
            ORDER BY d.id DESC
            """
        )

        delivery_list = cursor.fetchall()

        cursor.execute(
            """
            SELECT
                id,
                name,
                sku,
                stock
            FROM products
            ORDER BY name
            """
        )

        product_list = cursor.fetchall()

        return render_template(
            "deliveries.html",
            deliveries=delivery_list,
            products=product_list
        )

    except mysql.connector.Error as e:

        if conn:
            conn.rollback()

        flash(f"Database error: {e}", "error")

        return redirect(url_for("deliveries"))

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# =========================================================
# VALIDATE DELIVERY
# =========================================================

@app.route("/deliveries/validate/<int:delivery_id>")
@login_required
def validate_delivery(delivery_id):

    conn = None
    cursor = None

    try:

        conn = connect_database()
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT *
            FROM deliveries
            WHERE id = %s
            """,
            (delivery_id,)
        )

        delivery = cursor.fetchone()

        if not delivery:
            flash("Delivery not found.", "error")
            return redirect(url_for("deliveries"))

        if delivery["status"] == "Done":
            flash("Delivery is already validated.", "error")
            return redirect(url_for("deliveries"))

        product_id = delivery["product_id"]
        quantity = float(delivery["quantity"])

        cursor.execute(
            """
            SELECT stock
            FROM products
            WHERE id = %s
            FOR UPDATE
            """,
            (product_id,)
        )

        product = cursor.fetchone()

        if not product:
            flash("Product not found.", "error")
            return redirect(url_for("deliveries"))

        previous_stock = float(product["stock"])

        if previous_stock < quantity:
            flash(
                "Insufficient stock for this delivery.",
                "error"
            )
            return redirect(url_for("deliveries"))

        new_stock = previous_stock - quantity

        cursor.execute(
            """
            UPDATE products
            SET stock = %s
            WHERE id = %s
            """,
            (
                new_stock,
                product_id
            )
        )

        # Deduct from warehouse stock rows
        remaining = quantity

        cursor.execute(
            """
            SELECT
                id,
                quantity
            FROM product_stock
            WHERE product_id = %s
              AND quantity > 0
            ORDER BY quantity DESC
            FOR UPDATE
            """,
            (product_id,)
        )

        stock_rows = cursor.fetchall()

        for row in stock_rows:

            if remaining <= 0:
                break

            available = float(row["quantity"])

            deduction = min(
                available,
                remaining
            )

            new_quantity = available - deduction

            cursor.execute(
                """
                UPDATE product_stock
                SET quantity = %s
                WHERE id = %s
                """,
                (
                    new_quantity,
                    row["id"]
                )
            )

            remaining -= deduction

        add_ledger_entry(
            cursor,
            product_id,
            "Delivery",
            -quantity,
            previous_stock,
            new_stock,
            delivery_id
        )

        cursor.execute(
            """
            UPDATE deliveries
            SET status = 'Done'
            WHERE id = %s
            """,
            (delivery_id,)
        )

        conn.commit()

        flash(
            "Delivery validated and stock reduced successfully.",
            "success"
        )

    except mysql.connector.Error as e:

        if conn:
            conn.rollback()

        flash(f"Database error: {e}", "error")

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()

    return redirect(url_for("deliveries"))


# =========================================================
# TRANSFERS
# =========================================================

@app.route("/transfers", methods=["GET", "POST"])
@login_required
def transfers():

    conn = None
    cursor = None

    try:

        conn = connect_database()
        cursor = conn.cursor(dictionary=True)

        if request.method == "POST":

            product_id = request.form.get("product_id", "").strip()
            from_location = request.form.get(
                "from_location",
                ""
            ).strip()
            to_location = request.form.get(
                "to_location",
                ""
            ).strip()
            quantity_value = request.form.get(
                "quantity",
                ""
            ).strip()

            if (
                not product_id
                or not from_location
                or not to_location
                or not quantity_value
            ):
                flash(
                    "Please fill all transfer fields.",
                    "error"
                )
                return redirect(url_for("transfers"))

            if from_location == to_location:
                flash(
                    "From and To locations must be different.",
                    "error"
                )
                return redirect(url_for("transfers"))

            try:
                quantity = float(quantity_value)
            except ValueError:
                flash(
                    "Quantity must be a number.",
                    "error"
                )
                return redirect(url_for("transfers"))

            if quantity <= 0:
                flash(
                    "Quantity must be greater than zero.",
                    "error"
                )
                return redirect(url_for("transfers"))

            transfer_number = (
                "TRF-" + secrets.token_hex(4).upper()
            )

            cursor.execute(
                """
                INSERT INTO transfers
                (
                    transfer_number,
                    product_id,
                    from_location,
                    to_location,
                    quantity,
                    status
                )
                VALUES (%s, %s, %s, %s, %s, 'Waiting')
                """,
                (
                    transfer_number,
                    product_id,
                    from_location,
                    to_location,
                    quantity
                )
            )

            conn.commit()

            flash(
                f"Transfer {transfer_number} created successfully.",
                "success"
            )

            return redirect(url_for("transfers"))

        cursor.execute(
            """
            SELECT
                t.id,
                t.transfer_number,
                t.from_location,
                t.to_location,
                t.quantity,
                t.status,
                t.created_at,
                p.name AS product_name,
                p.sku
            FROM transfers t
            JOIN products p
                ON t.product_id = p.id
            ORDER BY t.id DESC
            """
        )

        transfer_list = cursor.fetchall()

        cursor.execute(
            """
            SELECT
                id,
                name,
                sku,
                stock
            FROM products
            ORDER BY name
            """
        )

        product_list = cursor.fetchall()

        warehouses = get_warehouses()

        return render_template(
            "transfers.html",
            transfers=transfer_list,
            products=product_list,
            warehouses=warehouses
        )

    except mysql.connector.Error as e:

        if conn:
            conn.rollback()

        flash(f"Database error: {e}", "error")

        return redirect(url_for("transfers"))

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# =========================================================
# VALIDATE TRANSFER
# =========================================================

@app.route("/transfers/validate/<int:transfer_id>")
@login_required
def validate_transfer(transfer_id):

    conn = None
    cursor = None

    try:

        conn = connect_database()
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT *
            FROM transfers
            WHERE id = %s
            """,
            (transfer_id,)
        )

        transfer = cursor.fetchone()

        if not transfer:
            flash("Transfer not found.", "error")
            return redirect(url_for("transfers"))

        if transfer["status"] == "Done":
            flash("Transfer is already completed.", "error")
            return redirect(url_for("transfers"))

        product_id = transfer["product_id"]
        from_location = transfer["from_location"]
        to_location = transfer["to_location"]
        quantity = float(transfer["quantity"])

        # Find source warehouse by NAME
        cursor.execute(
            """
            SELECT id, name
            FROM warehouses
            WHERE name = %s
            """,
            (from_location,)
        )

        from_warehouse = cursor.fetchone()

        # Find destination warehouse by NAME
        cursor.execute(
            """
            SELECT id, name
            FROM warehouses
            WHERE name = %s
            """,
            (to_location,)
        )

        to_warehouse = cursor.fetchone()

        if not from_warehouse or not to_warehouse:
            flash(
                "Source or destination warehouse not found.",
                "error"
            )
            return redirect(url_for("transfers"))

        # Source stock
        cursor.execute(
            """
            SELECT quantity
            FROM product_stock
            WHERE product_id = %s
              AND warehouse_id = %s
            FOR UPDATE
            """,
            (
                product_id,
                from_warehouse["id"]
            )
        )

        source = cursor.fetchone()

        source_quantity = (
            float(source["quantity"])
            if source
            else 0
        )

        if source_quantity < quantity:
            flash(
                "Insufficient stock at the source warehouse.",
                "error"
            )
            return redirect(url_for("transfers"))

        # Reduce source
        new_source_quantity = source_quantity - quantity

        cursor.execute(
            """
            INSERT INTO product_stock
            (
                product_id,
                warehouse_id,
                quantity
            )
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE
            quantity = VALUES(quantity)
            """,
            (
                product_id,
                from_warehouse["id"],
                new_source_quantity
            )
        )

        # Add destination
        cursor.execute(
            """
            INSERT INTO product_stock
            (
                product_id,
                warehouse_id,
                quantity
            )
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE
            quantity = quantity + VALUES(quantity)
            """,
            (
                product_id,
                to_warehouse["id"],
                quantity
            )
        )

        # Total product stock does not change
        cursor.execute(
            """
            SELECT stock
            FROM products
            WHERE id = %s
            FOR UPDATE
            """,
            (product_id,)
        )

        product = cursor.fetchone()

        if product:

            total_stock = float(product["stock"])

            add_ledger_entry(
                cursor,
                product_id,
                "Internal Transfer",
                0,
                total_stock,
                total_stock,
                transfer_id
            )

        cursor.execute(
            """
            UPDATE transfers
            SET status = 'Done'
            WHERE id = %s
            """,
            (transfer_id,)
        )

        conn.commit()

        flash(
            "Internal transfer completed successfully.",
            "success"
        )

    except mysql.connector.Error as e:

        if conn:
            conn.rollback()

        flash(f"Database error: {e}", "error")

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()

    return redirect(url_for("transfers"))


# =========================================================
# ADJUSTMENTS
# =========================================================

@app.route("/adjustments", methods=["GET", "POST"])
@login_required
def adjustments():

    conn = None
    cursor = None

    try:

        conn = connect_database()
        cursor = conn.cursor(dictionary=True)

        if request.method == "POST":

            product_id = request.form.get("product_id", "").strip()
            location = request.form.get("location", "").strip()
            counted_quantity_value = request.form.get(
                "counted_quantity",
                ""
            ).strip()
            reason = request.form.get(
                "reason",
                ""
            ).strip()

            if (
                not product_id
                or not location
                or not counted_quantity_value
            ):
                flash(
                    "Please fill all adjustment fields.",
                    "error"
                )
                return redirect(url_for("adjustments"))

            try:
                counted_quantity = float(
                    counted_quantity_value
                )
            except ValueError:
                flash(
                    "Counted quantity must be a number.",
                    "error"
                )
                return redirect(url_for("adjustments"))

            if counted_quantity < 0:
                flash(
                    "Counted quantity cannot be negative.",
                    "error"
                )
                return redirect(url_for("adjustments"))

            # Find warehouse
            cursor.execute(
                """
                SELECT id
                FROM warehouses
                WHERE name = %s
                """,
                (location,)
            )

            warehouse = cursor.fetchone()

            if not warehouse:
                flash(
                    "Warehouse not found.",
                    "error"
                )
                return redirect(url_for("adjustments"))

            warehouse_id = warehouse["id"]

            # Existing warehouse stock
            cursor.execute(
                """
                SELECT quantity
                FROM product_stock
                WHERE product_id = %s
                  AND warehouse_id = %s
                FOR UPDATE
                """,
                (
                    product_id,
                    warehouse_id
                )
            )

            stock_row = cursor.fetchone()

            previous_location_stock = (
                float(stock_row["quantity"])
                if stock_row
                else 0
            )

            difference = (
                counted_quantity -
                previous_location_stock
            )

            # Total product stock
            cursor.execute(
                """
                SELECT stock
                FROM products
                WHERE id = %s
                FOR UPDATE
                """,
                (product_id,)
            )

            product = cursor.fetchone()

            if not product:
                flash(
                    "Product not found.",
                    "error"
                )
                return redirect(url_for("adjustments"))

            previous_total = float(product["stock"])
            new_total = previous_total + difference

            if new_total < 0:
                flash(
                    "Adjustment would make total stock negative.",
                    "error"
                )
                return redirect(url_for("adjustments"))

            # Update warehouse quantity
            cursor.execute(
                """
                INSERT INTO product_stock
                (
                    product_id,
                    warehouse_id,
                    quantity
                )
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE
                quantity = VALUES(quantity)
                """,
                (
                    product_id,
                    warehouse_id,
                    counted_quantity
                )
            )

            # Update total
            cursor.execute(
                """
                UPDATE products
                SET stock = %s
                WHERE id = %s
                """,
                (
                    new_total,
                    product_id
                )
            )

            adjustment_number = (
                "ADJ-" + secrets.token_hex(4).upper()
            )

            cursor.execute(
                """
                INSERT INTO adjustments
                (
                    adjustment_number,
                    product_id,
                    location,
                    counted_quantity,
                    previous_stock,
                    new_stock,
                    reason,
                    status
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'Done')
                """,
                (
                    adjustment_number,
                    product_id,
                    location,
                    counted_quantity,
                    previous_total,
                    new_total,
                    reason
                )
            )

            adjustment_id = cursor.lastrowid

            add_ledger_entry(
                cursor,
                product_id,
                "Inventory Adjustment",
                difference,
                previous_total,
                new_total,
                adjustment_id
            )

            conn.commit()

            flash(
                f"Adjustment {adjustment_number} completed successfully.",
                "success"
            )

            return redirect(url_for("adjustments"))

        cursor.execute(
            """
            SELECT
                a.id,
                a.adjustment_number,
                a.location,
                a.counted_quantity,
                a.previous_stock,
                a.new_stock,
                a.reason,
                a.status,
                a.created_at,
                p.name AS product_name,
                p.sku
            FROM adjustments a
            JOIN products p
                ON a.product_id = p.id
            ORDER BY a.id DESC
            """
        )

        adjustment_list = cursor.fetchall()

        cursor.execute(
            """
            SELECT
                id,
                name,
                sku,
                stock
            FROM products
            ORDER BY name
            """
        )

        product_list = cursor.fetchall()

        warehouses = get_warehouses()

        return render_template(
            "adjustments.html",
            adjustments=adjustment_list,
            products=product_list,
            warehouses=warehouses
        )

    except mysql.connector.Error as e:

        if conn:
            conn.rollback()

        flash(f"Database error: {e}", "error")

        return redirect(url_for("adjustments"))

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# =========================================================
# STOCK LEDGER
# =========================================================

@app.route("/ledger")
@login_required
def ledger():

    conn = None
    cursor = None

    try:

        conn = connect_database()
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT
                sl.id,
                sl.transaction_type,
                sl.quantity,
                sl.previous_stock,
                sl.new_stock,
                sl.reference_id,
                sl.created_at,
                p.name AS product_name,
                p.sku,
                p.unit
            FROM stock_ledger sl
            JOIN products p
                ON sl.product_id = p.id
            ORDER BY sl.created_at DESC
            """
        )

        ledger_entries = cursor.fetchall()

        return render_template(
            "ledger.html",
            ledger=ledger_entries
        )

    except mysql.connector.Error as e:

        flash(f"Database error: {e}", "error")

        return render_template(
            "ledger.html",
            ledger=[]
        )

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# =========================================================
# WAREHOUSES
# =========================================================

@app.route("/warehouses", methods=["GET", "POST"])
@login_required
def warehouses():

    conn = None
    cursor = None

    try:

        conn = connect_database()
        cursor = conn.cursor(dictionary=True)

        if request.method == "POST":

            name = request.form.get("name", "").strip()
            code = request.form.get("code", "").strip()
            address = request.form.get(
                "address",
                ""
            ).strip()

            status = request.form.get(
                "status",
                "Active"
            ).strip()

            if not name or not code:
                flash(
                    "Warehouse name and code are required.",
                    "error"
                )
                return redirect(url_for("warehouses"))

            cursor.execute(
                """
                SELECT id
                FROM warehouses
                WHERE code = %s
                """,
                (code,)
            )

            existing = cursor.fetchone()

            if existing:
                flash(
                    "Warehouse code already exists.",
                    "error"
                )
                return redirect(url_for("warehouses"))

            cursor.execute(
                """
                INSERT INTO warehouses
                (
                    name,
                    code,
                    address,
                    status
                )
                VALUES (%s, %s, %s, %s)
                """,
                (
                    name,
                    code,
                    address,
                    status
                )
            )

            conn.commit()

            flash(
                "Warehouse added successfully.",
                "success"
            )

            return redirect(url_for("warehouses"))

        cursor.execute(
            """
            SELECT
                id,
                name,
                code,
                address,
                status,
                created_at
            FROM warehouses
            ORDER BY id DESC
            """
        )

        warehouse_list = cursor.fetchall()

        return render_template(
            "warehouses.html",
            warehouses=warehouse_list
        )

    except mysql.connector.Error as e:

        if conn:
            conn.rollback()

        flash(f"Database error: {e}", "error")

        return redirect(url_for("warehouses"))

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# =========================================================
# SETTINGS
# =========================================================

@app.route("/settings")
@login_required
def settings():

    warehouses = get_warehouses()

    return render_template(
        "settings.html",
        warehouses=warehouses
    )


# =========================================================
# PROFILE
# =========================================================

@app.route("/profile")
@login_required
def profile():

    return render_template(
        "profile.html",
        user_name=session.get(
            "user_name",
            "Admin"
        ),
        user_email=session.get(
            "user_email",
            ""
        ),
        user_role=session.get(
            "user_role",
            "Inventory Manager"
        )
    )


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":
    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )