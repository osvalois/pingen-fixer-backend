from flask import request, url_for, current_app
from mongoengine.queryset.base import BaseQuerySet
import math

def paginate(query, schema=None, **kwargs):
    """
    Paginate a query or list of items.
    
    :param query: The query or list to paginate
    :param schema: Optional schema to serialize the results
    :param kwargs: Additional arguments to pass to the schema
    :return: A dictionary containing pagination info and results
    """
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', current_app.config.get('ITEMS_PER_PAGE', 20), type=int)
    
    # Ensure per_page doesn't exceed the maximum allowed
    max_per_page = current_app.config.get('MAX_ITEMS_PER_PAGE', 100)
    per_page = min(per_page, max_per_page)

    # Handle different types of queries
    if isinstance(query, BaseQuerySet):
        total = query.count()
        items = query.skip((page - 1) * per_page).limit(per_page)
    elif isinstance(query, list):
        total = len(query)
        items = query[(page - 1) * per_page:page * per_page]
    else:
        raise ValueError("Unsupported query type for pagination")

    # Calculate pagination metadata
    last_page = math.ceil(total / per_page)
    next_page = page + 1 if page < last_page else None
    prev_page = page - 1 if page > 1 else None

    # Serialize items if a schema is provided
    if schema:
        items = schema.dump(items, many=True, **kwargs)

    return {
        'items': items,
        'pagination': {
            'total': total,
            'per_page': per_page,
            'current_page': page,
            'last_page': last_page,
            'next_page': next_page,
            'prev_page': prev_page,
            'from': (page - 1) * per_page + 1,
            'to': min(page * per_page, total)
        }
    }

def get_pagination_links(pagination):
    """
    Generate pagination links for the response headers.
    
    :param pagination: The pagination info from the paginate function
    :return: A dictionary of pagination links
    """
    links = {}
    base_url = request.base_url
    
    def get_url(page):
        return url_for(request.endpoint, page=page, per_page=pagination['per_page'], **request.view_args, _external=True)

    links['self'] = get_url(pagination['current_page'])
    
    if pagination['next_page']:
        links['next'] = get_url(pagination['next_page'])
    
    if pagination['prev_page']:
        links['prev'] = get_url(pagination['prev_page'])
    
    links['first'] = get_url(1)
    links['last'] = get_url(pagination['last_page'])

    return links

def set_pagination_headers(response, pagination):
    """
    Set pagination headers on the response.
    
    :param response: The Flask response object
    :param pagination: The pagination info from the paginate function
    :return: The modified response object
    """
    links = get_pagination_links(pagination['pagination'])
    link_header = ', '.join([f'<{url}>; rel="{rel}"' for rel, url in links.items()])
    response.headers['Link'] = link_header
    response.headers['X-Total-Count'] = str(pagination['pagination']['total'])
    return response