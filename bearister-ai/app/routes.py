import email.utils as email_utils
from app import utils
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from app import models, schemas, auth, database
from app.dependencies import get_current_user
from app.utils import send_verification_email
import secrets
from passlib.context import CryptContext
import logging

logger = logging.getLogger(__name__)
router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()




#superadmin registration 

@router.post("/superadmin/register", response_model=schemas.UserCreate)   
def register_superadmin(user: schemas.UserCreate, db: Session = Depends(get_db)):
    # normalize email for lookup
    email_clean = user.email.strip().lower()
    logger.info("Attempt register_superadmin for email=%s", email_clean)
    db_user = db.query(models.User).filter(func.lower(models.User.email) == email_clean).first()
    if db_user:
        logger.info("Duplicate user found during superadmin register: %s (id=%s)", db_user.email, getattr(db_user, 'id', None))
        raise HTTPException(status_code=400, detail="Email already registered")


    hashed_password = auth.hash_password(user.password)
    new_superadmin = models.User(
        full_name=user.full_name,
        email=email_clean,
        password=hashed_password,
        is_superadmin=True
    )
    db.add(new_superadmin)
    db.commit()
    db.refresh(new_superadmin)
    return new_superadmin



# ----------------------------
# Super Admin Login



# Super Admin Login
# ----------------------------
@router.post("/superadmin/login", response_model=schemas.TokenWithUser)
def login_superadmin(user: schemas.UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(
        models.User.email == user.email, models.User.is_superadmin == True
    ).first()

    if not db_user or not auth.verify_password(user.password, db_user.password):
        raise HTTPException(status_code=401, detail="Invalid super admin credentials")

    access_token = auth.create_access_token({"sub": str(db_user.id), "role": "superadmin"})
    refresh_token = auth.create_refresh_token({"sub": str(db_user.id), "role": "superadmin"})

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "role": "superadmin",
        "user": db_user
    }
#user Register
@router.post("/register", response_model=schemas.MessageResponse)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    if not user.agree_terms:
        raise HTTPException(status_code=400, detail="You must agree to the Terms and Conditions and Privacy Policy.")
    # normalize and check case-insensitively
    email_clean = user.email.strip().lower()
    logger.info("Attempt register for email=%s", email_clean)
    db_user = db.query(models.User).filter(func.lower(models.User.email) == email_clean).first()
    if db_user:
        logger.info("Duplicate user found during register: %s (id=%s)", db_user.email, getattr(db_user, 'id', None))
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = auth.hash_password(user.password)
    new_user = models.User(
        full_name=user.full_name,
        email=email_clean,
        password=hashed_password,
        agree_terms=user.agree_terms,
        is_verified=False
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    
    # Generate token and send verification email
    token = utils.create_verification_token(new_user.email)
    utils.send_verification_email(new_user.email, token)
    # return new_user
    return {"message": "User registered successfully. Please check your email to verify your account."}


# verify endpoint
@router.get("/verify-email")
def verify_email(token: str = Query(...), db: Session = Depends(get_db)):
    email = utils.verify_verification_token(token)
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    user.is_verified = True
    user.verification_token = None
    db.commit()
    return {"message": f"Email {email} verified successfully"}





# ----------------------------
# User Login
# User Login
@router.post("/login", response_model=schemas.Token)
def login_user(user: schemas.UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(
        models.User.email == user.email, models.User.is_superadmin == False
    ).first()

    if not db_user or not auth.verify_password(user.password, db_user.password):
        raise HTTPException(status_code=401, detail="Invalid user credentials")
    # Require email verification before allowing login
    if not db_user.is_verified:
        raise HTTPException(status_code=403, detail="Email not verified. Please check your inbox.")

    access_token = auth.create_access_token({"sub": str(db_user.id), "role": "user"})
    refresh_token = auth.create_refresh_token({"sub": str(db_user.id), "role": "user"})

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "role": "user",
        "user": db_user
    }




@router.post("/refresh", response_model=schemas.Token)
def refresh_token(refresh_token: str, db: Session = Depends(get_db)):
    # Decode refresh token
    payload = auth.verify_token(refresh_token)
    user_id: str = payload.get("sub")
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    
    # Check if user still exists
    db_user = db.query(models.User).filter(models.User.id == int(user_id)).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Generate new access + refresh tokens
    new_access_token = auth.create_access_token({"sub": str(db_user.id)})
    new_refresh_token = auth.create_refresh_token({"sub": str(db_user.id)})

    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
        "user": db_user
    }



# ✅ Get Profile
@router.get("/profile")
def get_profile(current_user: models.User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "full_name": current_user.full_name,
        "email": current_user.email,
        "phone": current_user.phone,
    }




# ✅ Update Profile
# from fastapi.responses import JSONResponse

# @router.put("/update_profile")
# def update_profile(
#     user_update: schemas.UserProfileUpdate,
#     db: Session = Depends(get_db),
#     current_user: models.User = Depends(get_current_user),
# ):
#     db_user = db.query(models.User).filter(models.User.id == current_user.id).first()
#     if not db_user:
#         raise HTTPException(status_code=404, detail="User not found")

#     if user_update.full_name:
#         db_user.full_name = user_update.full_name
#     if user_update.phone:
#         db_user.phone = user_update.phone

#     db.commit()
#     db.refresh(db_user)

#     return {
#         "message": "Profile Updated Successfully",
#         "user": db_user
#     }

@router.put("/update_profile", response_model=schemas.UserProfile)
def update_profile(
    user_update: schemas.UserProfileUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    db_user = db.query(models.User).filter(models.User.id == current_user.id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    if user_update.full_name:
        db_user.full_name = user_update.full_name
    if user_update.email:
        db_user.email = user_update.email   
    if user_update.phone:
        db_user.phone = user_update.phone

    db.commit()
    db.refresh(db_user)

    return db_user


@router.put("/update_password")
def update_password(
    request: schemas.UpdatePasswordRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    db_user = db.query(models.User).filter(models.User.id == current_user.id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    # check old password
    if not auth.verify_password(request.old_password, db_user.password):  # <-- use correct field
        raise HTTPException(status_code=400, detail="Old password is incorrect")

    # update new password
    db_user.password = auth.hash_password(request.new_password)  # <-- update correct field
    db.commit()
    db.refresh(db_user)

    return {"message": "Password updated successfully"}
