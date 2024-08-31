from mongoengine import Document, StringField, ReferenceField, ListField, EmailField, DateTimeField, BooleanField, IntField, DictField, EmbeddedDocument, EmbeddedDocumentField
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
import pytz

class Company(Document):
    name = StringField(required=True, unique=True)
    description = StringField()
    industry = StringField()
    size = StringField(choices=['Small', 'Medium', 'Large', 'Enterprise'])
    website = StringField()
    headquarters = StringField()
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)

    meta = {
        'indexes': [
            {'fields': ['name'], 'unique': True}
        ]
    }

    def clean(self):
        self.updated_at = datetime.utcnow()

class User(Document):
    name = StringField(required=True)
    username = StringField(required=True, unique=True)
    email = EmailField(required=True, unique=True)
    password_hash = StringField(required=True)
    role = StringField(choices=['admin', 'manager', 'user'], default='user')
    is_active = BooleanField(default=True)
    is_verified = BooleanField(default=False)
    verification_token = StringField()
    company = ReferenceField(Company)
    preferred_language = StringField(default='en')
    timezone = StringField(default='UTC')
    last_login = DateTimeField()
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)

    meta = {
        'indexes': [
            {'fields': ['username'], 'unique': True},
            {'fields': ['email'], 'unique': True}
        ]
    }

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        
    def to_dict(self):
        return {
            'id': str(self.id),
            'name': self.name,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'company': str(self.company.id) if self.company else None,
            'preferred_language': self.preferred_language,
            'timezone': self.timezone
        }

    def clean(self):
        self.updated_at = datetime.utcnow()

class Project(Document):
    name = StringField(required=True)
    description = StringField()
    company = ReferenceField(Company, required=True)
    status = StringField(choices=['Planning', 'In Progress', 'Completed', 'On Hold'], default='Planning')
    start_date = DateTimeField()
    end_date = DateTimeField()
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)

    meta = {
        'indexes': [
            {'fields': ['company', 'name'], 'unique': True}
        ]
    }

    def clean(self):
        self.updated_at = datetime.utcnow()

class UserProjectAccess(Document):
    user = ReferenceField(User, required=True)
    project = ReferenceField(Project, required=True)
    access_level = StringField(choices=['read', 'write', 'admin'], default='read')
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)

    meta = {
        'indexes': [
            {'fields': ['user', 'project'], 'unique': True}
        ]
    }

    def clean(self):
        self.updated_at = datetime.utcnow()

class Suggestion(Document):
    issue_key = StringField(required=True)
    suggestion = StringField(required=True)
    project = ReferenceField(Project, required=True)
    created_by = ReferenceField(User, required=True)
    status = StringField(choices=['New', 'In Review', 'Accepted', 'Rejected'], default='New')
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)

    meta = {
        'indexes': [
            {'fields': ['project', 'issue_key']}
        ]
    }

    def clean(self):
        self.updated_at = datetime.utcnow()

class RefreshToken(Document):
    user = ReferenceField(User, required=True)
    token = StringField(required=True, unique=True)
    expires_at = DateTimeField(required=True)
    created_at = DateTimeField(default=datetime.utcnow)

    meta = {
        'indexes': [
            {'fields': ['token'], 'unique': True},
            {'fields': ['user', 'expires_at']}
        ]
    }

    @classmethod
    def generate_token(cls, user, expires_delta=timedelta(days=30)):
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + expires_delta
        refresh_token = cls(user=user, token=token, expires_at=expires_at)
        refresh_token.save()
        return token

    def is_valid(self):
        return datetime.utcnow() < self.expires_at

class PasswordResetToken(Document):
    user = ReferenceField(User, required=True)
    token = StringField(required=True, unique=True)
    created_at = DateTimeField(default=datetime.utcnow)
    expires_at = DateTimeField()

    meta = {
        'indexes': [
            {'fields': ['token'], 'unique': True},
            {'fields': ['user', 'expires_at']}
        ]
    }

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = self.created_at + timedelta(hours=24)
        return super(PasswordResetToken, self).save(*args, **kwargs)

    def is_expired(self):
        return datetime.utcnow() > self.expires_at

class AuditLog(Document):
    user = ReferenceField(User)
    action = StringField(required=True)
    details = DictField()
    ip_address = StringField()
    timestamp = DateTimeField(default=datetime.utcnow)

    meta = {
        'indexes': [
            {'fields': ['-timestamp']},
            {'fields': ['user', '-timestamp']}
        ]
    }

class Notification(Document):
    user = ReferenceField(User, required=True)
    message = StringField(required=True)
    type = StringField(required=True)
    is_read = BooleanField(default=False)
    created_at = DateTimeField(default=datetime.utcnow)

    meta = {
        'indexes': [
            {'fields': ['user', '-created_at']}
        ]
    }

class Settings(Document):
    key = StringField(required=True, unique=True)
    value = StringField(required=True)
    description = StringField()

    meta = {
        'indexes': [
            {'fields': ['key'], 'unique': True}
        ]
    }