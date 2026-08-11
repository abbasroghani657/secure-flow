import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sqlmodel import Session, select
from app.database import engine
from app.models import User

def main():
    if len(sys.argv) < 2:
        print("Usage: python make_admin.py <user_email>")
        sys.exit(1)
        
    target_email = sys.argv[1].lower()
    
    with Session(engine) as session:
        user = session.exec(select(User).where(User.email == target_email)).first()
        if not user:
            print(f"[-] User {target_email} not found in database.")
            sys.exit(1)
            
        user.is_superuser = True
        user.admin_role = "superadmin"
        session.add(user)
        session.commit()
        
        print(f"[+] SUCCESS! {target_email} has been promoted to Supreme-Tier Admin.")
        print("    You can now access the Omniscience Engine at /admin")

if __name__ == "__main__":
    main()
