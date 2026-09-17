import chromadb

def retrieve(query, tenant_id):
    return collection.similarity_search(query, filter={"tenant_id": tenant_id})
