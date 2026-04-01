import os
import uuid
import shutil
from typing import List, Dict, Any

import fitz  # PyMuPDF
from sentence_transformers import SentenceTransformer
import chromadb
from chromadb.config import Settings

# Create a local directory for ChromaDB storage
DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rag_db")
DOCS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rag_docs")

os.makedirs(DB_DIR, exist_ok=True)
os.makedirs(DOCS_DIR, exist_ok=True)


class RAGService:
    def __init__(self):
        print("Initializing RAG Service...")
        
        # 1. Initialize Vector Database (ChromaDB)
        self.chroma_client = chromadb.PersistentClient(path=DB_DIR)
        
        # We use a single collection for all RAG documents for simplicity
        self.collection = self.chroma_client.get_or_create_collection(
            name="CloudSecurityApp_rag"
        )
        
        # 2. Initialize Embeddings Model (Local, Free)
        # all-MiniLM-L6-v2 is small, fast, and very effective for standard local RAG
        print("Loading embedding model (this may take a moment on first run)...")
        self.embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
        print("RAG Service Initialized!")

    def _chunk_text(self, text: str, chunk_size: int = 1000, overlap: int = 200) -> List[str]:
        """Split text into manageable chunks with overlap to retain context across boundaries."""
        chunks = []
        start = 0
        text_length = len(text)
        
        while start < text_length:
            end = start + chunk_size
            chunks.append(text[start:end])
            start = end - overlap
            
        return chunks

    def ingest_pdf(self, file_path: str, filename: str) -> Dict[str, Any]:
        """Extract text from PDF, chunk it, embed it, and store it in ChromaDB."""
        try:
            # 1. Extract Text using PyMuPDF (fitz)
            doc = fitz.open(file_path)
            full_text = ""
            for page in doc:
                full_text += page.get_text()
            
            if not full_text.strip():
                return {"success": False, "error": "No extractable text found in PDF."}

            # 2. Chunk the text
            chunks = self._chunk_text(full_text)
            if not chunks:
                 return {"success": False, "error": "Failed to chunk the text."}

            doc_id = str(uuid.uuid4())
            
            # 3. Create Embeddings
            embeddings = self.embedding_model.encode(chunks).tolist()
            
            # 4. Store in ChromaDB
            ids = [f"{doc_id}_chunk_{i}" for i in range(len(chunks))]
            metadatas = [{"source": filename, "doc_id": doc_id, "chunk_index": i} for i in range(len(chunks))]
            
            self.collection.add(
                embeddings=embeddings,
                documents=chunks,
                metadatas=metadatas,
                ids=ids
            )
            
            return {
                "success": True, 
                "doc_id": doc_id, 
                "filename": filename, 
                "chunks_processed": len(chunks)
            }
        except Exception as e:
            print(f"Error ingesting PDF: {e}")
            return {"success": False, "error": str(e)}

    def get_all_documents(self) -> List[Dict[str, str]]:
        """Retrieve a list of all unique documents currently stored in the DB."""
        # Querying everything just to get metadatas (Chroma doesn't easily group by metadata)
        # For small scale RAG this is fine.
        results = self.collection.get(include=["metadatas"])
        
        unique_docs = {}
        if results and results["metadatas"]:
            for meta in results["metadatas"]:
                if meta:
                    doc_id = meta.get("doc_id")
                    if doc_id and doc_id not in unique_docs:
                        unique_docs[doc_id] = {
                            "id": doc_id,
                            "filename": meta.get("source", "Unknown Document")
                        }
        
        return list(unique_docs.values())

    def delete_document(self, doc_id: str) -> bool:
        """Delete all chunks belonging to a specific document."""
        try:
            # Delete from collection based on metadata doc_id
            self.collection.delete(
                where={"doc_id": doc_id}
            )
            return True
        except Exception as e:
            print(f"Error deleting document {doc_id}: {e}")
            return False

    def query_documents(self, query: str, n_results: int = 4) -> str:
        """Search the vector DB for context relevant to the user's query."""
        try:
            # 1. Embed the user's query
            query_embedding = self.embedding_model.encode([query]).tolist()
            
            # 2. Search ChromaDB
            results = self.collection.query(
                query_embeddings=query_embedding,
                n_results=n_results,
                include=["documents", "metadatas"]
            )
            
            # 3. Assemble the raw context string
            context_pieces = []
            if results and results['documents'] and len(results['documents'][0]) > 0:
                for i, doc_chunk in enumerate(results['documents'][0]):
                    source_name = results['metadatas'][0][i].get("source", "Unknown")
                    context_pieces.append(f"[Source: {source_name}]\n{doc_chunk}")
                    
            if not context_pieces:
                return "No relevant context found in documents."
                
            return "\n\n---\n\n".join(context_pieces)
            
        except Exception as e:
            print(f"Error querying documents: {e}")
            return f"Error retrieving context: {str(e)}"
