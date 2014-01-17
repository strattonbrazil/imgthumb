from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy import create_engine
from sqlalchemy.schema import ThreadLocalMetaData
from elixir import *
from datetime import datetime

refEngine = create_engine('sqlite:////tmp/gazette_ref.db', echo=True)
refSession = scoped_session(sessionmaker(autoflush=True, bind=refEngine))
refMetadata = metadata
refMetadata.bind = refEngine

prodEngine = create_engine("sqlite:////tmp/gazette.db", echo=False)
prodSession = scoped_session(sessionmaker(autoflush=True, bind=prodEngine))
prodMetadata = ThreadLocalMetaData()
prodMetadata.bind = prodEngine

#metadata.bind = "sqlite:////tmp/gazette.db"
#metadata.bind.echo = True

class Author(Entity):
    name = Field(UnicodeText)
    using_options(metadata=prodMetadata, session=prodSession)

class User(Entity):
    email = Field(UnicodeText)
    using_options(metadata=prodMetadata, session=prodSession)

class Article(Entity):
    title = Field(UnicodeText)
    markdown = Field(UnicodeText)
    created = Field(DateTime)
    owner = ManyToOne(User)
    author = ManyToOne(Author)
    published = Field(Boolean)
    category = Field(UnicodeText)
    using_options(metadata=prodMetadata, session=prodSession)

