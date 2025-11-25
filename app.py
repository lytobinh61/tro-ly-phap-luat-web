from datetime import date, timedelta
import os
from dotenv import load_dotenv
from openai import OpenAI
from flask import Flask, render_template, redirect, url_for, request, jsonify
from flask_login import (
    LoginManager, login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from openai import OpenAI

from models import db, User
from functools import wraps
from datetime import datetime  # ngoài date, timedelta đã có
from flask import flash        # để hiện thông báo


# ====== CẤU HÌNH FLASK & DB ======

app = Flask(__name__)
app.config["SECRET_KEY"] = "thay-chuoi-nay-bang-bi-mat-cua-ban"

# SQLite: file app.db nằm cùng thư mục app.py
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

# Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    """Chỉ cho phép user là admin truy cập."""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin():
            flash("Bạn không có quyền truy cập trang admin.")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function


def auto_lock_expired_users():
    """Tự động khóa (is_active_flag = False) cho user đã hết hạn."""
    today = date.today()
    expired_users = User.query.filter(
        User.expire_date < today,
        User.is_active_flag == True
    ).all()

    if expired_users:
        for u in expired_users:
            u.is_active_flag = False
        db.session.commit()


# ====== CẤU HÌNH OPENAI ======


load_dotenv()

API_KEY = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=API_KEY)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "secret-tam")

INSTRUCTIONS = """
Bạn là “Trợ lý phân tích văn bản pháp luật”. Mục tiêu: hỗ trợ người dùng làm việc với nghị định, thông tư (đọc, phân tích, tóm tắt, giải thích, so sánh), theo kịch bản bấm-nút rõ ràng, dễ thao tác. Luôn dùng tiếng Việt, giọng rõ ràng, ngắn gọn, thân thiện. Không chèn cảnh báo pháp lý.

Cách tương tác mặc định (màn hình đầu): hiển thị hai lựa chọn dạng nút:
👉 [Tìm hiểu văn bản]   👉 [Tìm kiếm theo chủ đề]

Quy tắc luồng “Tìm hiểu văn bản”:
1) Khi người dùng bấm “Tìm hiểu văn bản”, yêu cầu họ nhập **số hiệu** văn bản (ví dụ: 15/2023/NĐ-CP, 12/2022/TT-BTC). 
2) **Ngay sau khi nhận số hiệu, KHÔNG hiển thị nội dung hay trích dẫn của văn bản.** Thay vào đó, chỉ hiển thị danh sách lựa chọn **đánh số** để người dùng nhập số lựa chọn:
   1. Phân tích văn bản  
   2. So sánh văn bản với văn bản khác  
   3. Tóm tắt điểm mới  
   4. Giải thích điều khoản
3) Khi người dùng chọn một số:
   - 1: cung cấp phân tích có cấu trúc (nội dung chính, phạm vi áp dụng, hiệu lực, căn cứ pháp lý...)
   - 2: nếu mới có 1 số hiệu, yêu cầu người dùng cung cấp số hiệu thứ hai. Khi đủ 2 văn bản, so sánh theo gạch đầu dòng: phạm vi, hiệu lực, định nghĩa, nghĩa vụ, chế tài, điểm mới.
   - 3: tóm tắt cô đọng (5–8 gạch đầu dòng) + 1 dòng TL;DR nếu phù hợp.
   - 4: nếu người dùng chưa nêu điều khoản/thuật ngữ, hỏi ngắn gọn để chỉ rõ; sau đó giải thích dễ hiểu, có ví dụ nếu phù hợp.
4) Sau khi hoàn thành bất kỳ tác vụ nào (1–4), luôn hiển thị lại **menu đánh số** với đúng nội dung và thứ tự:
   1. Phân tích văn bản  
   2. So sánh văn bản với văn bản khác  
   3. Tóm tắt điểm mới  
   4. Giải thích điều khoản
   0. Chuyển sang lựa chọn khác

Quy tắc luồng “Tìm kiếm theo chủ đề”:
1) Khi bấm “Tìm kiếm theo chủ đề”, yêu cầu người dùng nhập **chủ đề** (ví dụ: hóa đơn điện tử, an toàn lao động…).
2) Sau khi nhận chủ đề, **tìm và hiển thị số hiệu nghị định/thông tư mới nhất** áp dụng cho chủ đề (kèm ngày ban hành/ngày hiệu lực và cơ quan ban hành nếu tra được). Khi có năng lực duyệt web, hãy dùng trình duyệt để kiểm tra tính cập nhật; nếu không thể xác minh, nói rõ hạn chế và đề nghị người dùng cung cấp số hiệu nếu họ đã có.
3) Sau khi hiển thị số hiệu, luôn hiển thị lại **menu đánh số giống hệt như sau bước nhập số hiệu văn bản**, kèm lựa chọn:
   0. Chuyển sang lựa chọn khác

Yêu cầu bắt buộc:
- **Không được thay đổi nội dung và thứ tự của 4 mục lựa chọn**.
- **Chỉ thêm mục 0 với nhãn “Chuyển sang lựa chọn khác”** để cho phép người dùng quay lại menu đầu.
- Trình bày rõ ràng, có tiêu đề và danh sách nếu phù hợp.
- Tránh lặp lại nội dung dài không cần thiết.
- Không tự động trích toàn văn văn bản nếu không được yêu cầu cụ thể.
"""


def call_gpt(user_text: str) -> str:
    """Gọi GPT với instructions của bạn."""
    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": INSTRUCTIONS},
                {"role": "user", "content": user_text},
            ],
        )
        return resp.choices[0].message.content
    except Exception as e:
        return f"❌ Lỗi khi gọi GPT: {e}"


# ====== ROUTE GIAO DIỆN ======

@app.route("/")
@login_required
def index():
    # Trang chính sẽ render index.html
    return render_template("index.html", username=current_user.username)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        # Mỗi lần có người đăng nhập thì dọn dẹp user hết hạn
        auto_lock_expired_users()

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()

        if not user:
            error = "Tài khoản không tồn tại."
        elif not check_password_hash(user.password_hash, password):
            error = "Mật khẩu không đúng."
        elif not user.is_active():
            # is_active() lấy theo is_active_flag + expire_date
            error = f"Tài khoản đã hết hạn hoặc bị khóa. Hạn dùng: {user.expire_date}"
        else:
            login_user(user)
            return redirect(url_for("index"))

    return render_template("login.html", error=error)



@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# ====== TRANG ADMIN QUẢN LÝ USER ======

@app.route("/admin")
@admin_required
def admin_dashboard():
    auto_lock_expired_users()  # thêm dòng này
    users = User.query.order_by(User.id).all()
    return render_template("admin.html", users=users)


@app.route("/admin/create", methods=["POST"])
@admin_required
def admin_create_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    expire_date_str = request.form.get("expire_date", "")
    is_active = True if request.form.get("is_active") == "on" else False
    is_admin = True if request.form.get("is_admin") == "on" else False

    if not username or not password or not expire_date_str:
        flash("Vui lòng nhập đầy đủ: tài khoản, mật khẩu, ngày hết hạn.")
        return redirect(url_for("admin_dashboard"))

    # Parse ngày hết hạn
    try:
        expire_date = datetime.strptime(expire_date_str, "%Y-%m-%d").date()
    except ValueError:
        flash("Ngày hết hạn không đúng định dạng.")
        return redirect(url_for("admin_dashboard"))

    # Kiểm tra trùng username
    if User.query.filter_by(username=username).first():
        flash("Tài khoản này đã tồn tại.")
        return redirect(url_for("admin_dashboard"))

    new_user = User(
        username=username,
        password_hash=generate_password_hash(password),
        expire_date=expire_date,
        is_active_flag=is_active,
        is_admin_flag=is_admin,
    )
    db.session.add(new_user)
    db.session.commit()
    flash("Đã tạo tài khoản mới.")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/<int:user_id>/edit", methods=["GET", "POST"])
@admin_required
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == "POST":
        # Không cho sửa username ở đây để tránh rối
        expire_date_str = request.form.get("expire_date", "")
        is_active = True if request.form.get("is_active") == "on" else False
        is_admin = True if request.form.get("is_admin") == "on" else False
        new_password = request.form.get("password", "")

        try:
            user.expire_date = datetime.strptime(expire_date_str, "%Y-%m-%d").date()
        except ValueError:
            flash("Ngày hết hạn không đúng định dạng.")
            return redirect(url_for("admin_edit_user", user_id=user.id))

        user.is_active_flag = is_active
        user.is_admin_flag = is_admin

        if new_password.strip():
            user.password_hash = generate_password_hash(new_password.strip())

        db.session.commit()
        flash("Đã cập nhật tài khoản.")
        return redirect(url_for("admin_dashboard"))

    # GET: hiển thị form sửa
    return render_template("edit_user.html", user=user)
# ====== GIA HẠN NHANH 30 / 60 / 90 / 180 NGÀY ======

def _extend_user_days(user_id, days):
    user = User.query.get_or_404(user_id)

    # Nếu đã hết hạn rồi thì tính lại từ hôm nay
    today = date.today()
    if user.expire_date < today:
        user.expire_date = today + timedelta(days=days)
    else:
        user.expire_date = user.expire_date + timedelta(days=days)

    # Gia hạn xong thì tự động mở lại cho phép đăng nhập
    user.is_active_flag = True

    db.session.commit()
    flash(
        f"Đã gia hạn thêm {days} ngày cho tài khoản: {user.username} "
        f"(tài khoản đã được mở khóa nếu trước đó bị khóa/hết hạn)."
    )



@app.route("/admin/<int:user_id>/extend/30")
@admin_required
def admin_extend_30(user_id):
    _extend_user_days(user_id, 30)
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/<int:user_id>/extend/60")
@admin_required
def admin_extend_60(user_id):
    _extend_user_days(user_id, 60)
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/<int:user_id>/extend/90")
@admin_required
def admin_extend_90(user_id):
    _extend_user_days(user_id, 90)
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/<int:user_id>/extend/180")
@admin_required
def admin_extend_180(user_id):
    _extend_user_days(user_id, 180)
    return redirect(url_for("admin_dashboard"))


# API để front-end gọi GPT
@app.route("/api/send", methods=["POST"])
@login_required
def api_send():
    data = request.get_json()
    text = (data or {}).get("text", "").strip()

    if not text:
        return jsonify({"reply": "⚠ Bạn chưa nhập nội dung."})

    reply = call_gpt(text)
    return jsonify({"reply": reply})


def tao_user_mac_dinh():
    """Tạo tài khoản admin mặc định lần đầu."""
    if User.query.count() == 0:
        username = "admin"
        mat_khau = "admin123"

        user = User(
            username=username,
            password_hash=generate_password_hash(mat_khau),
            expire_date=date.today() + timedelta(days=365),
            is_active_flag=True,
            is_admin_flag=True,   # <– thêm dòng này
        )

        db.session.add(user)
        db.session.commit()
        print("Đã tạo user mặc định:")
        print(f"  username: {username}")
        print(f"  password: {mat_khau}")
        print(f"  hết hạn: {user.expire_date}")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        tao_user_mac_dinh()

    # host="0.0.0.0" = cho phép máy khác trong mạng truy cập
    app.run(debug=True, host="0.0.0.0", port=5000)
