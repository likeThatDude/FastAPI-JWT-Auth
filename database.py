from sqlalchemy import create_engine, String
from sqlalchemy.orm import Mapped, mapped_column, sessionmaker, as_declarative, declared_attr

engine = create_engine('sqlite:///test.db', echo=False)
session_factory = sessionmaker(engine)


@as_declarative()
class Base:
    @classmethod
    @declared_attr
    def __tablename__(cls):
        return f'{cls.__name__.lower()}s'


class User(Base):
    id: Mapped[int] = mapped_column(autoincrement=True, primary_key=True, nullable=False)
    username: Mapped[str] = mapped_column(String(length=20), nullable=False)
    email: Mapped[str] = mapped_column(nullable=False, unique=True)
    hashed_password: Mapped[str] = mapped_column(nullable=False)


# with session_factory() as session:
#     Base.metadata.drop_all(engine)
#     Base.metadata.create_all(engine)


def get_session():
    with session_factory() as session:
        yield session
