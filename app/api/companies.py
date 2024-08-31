from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from app.models import Company
from app.auth import admin_required

bp = Blueprint('companies', __name__, url_prefix='/api/companies')

@bp.route('/', methods=['POST'])
@jwt_required()
@admin_required
def create_company():
    data = request.json
    company = Company(**data).save()
    return jsonify(company), 201

@bp.route('/', methods=['GET'])
@jwt_required()
@admin_required
def get_companies():
    companies = Company.objects.all()
    return jsonify(companies), 200

@bp.route('/<id>', methods=['GET'])
@jwt_required()
def get_company(id):
    company = Company.objects.get(id=id)
    return jsonify(company), 200

@bp.route('/<id>', methods=['PUT'])
@jwt_required()
@admin_required
def update_company(id):
    data = request.json
    Company.objects.get(id=id).update(**data)
    return jsonify({"message": "Company updated successfully"}), 200

@bp.route('/<id>', methods=['DELETE'])
@jwt_required()
@admin_required
def delete_company(id):
    Company.objects.get(id=id).delete()
    return jsonify({"message": "Company deleted successfully"}), 200