from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


class GameSystem(Base):
    __tablename__= 'gameSystem'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
		"""Return object data in easily serializeable format"""
		return {
			'name': self.name,
			'id': self.id
		}


class Game(Base):
	__tablename__= 'game'

	name = Column(String(80), nullable=False)
	id = Column(Integer, primary_key=True)
	description = Column(String(300))    
	gameSystem_id = Column(Integer, ForeignKey('gameSystem.id'))
	gameSystem = relationship(GameSystem)
	user_id = Column(Integer, ForeignKey('user.id'))
	user = relationship(User)

	@property
	def serialize(self):
		"""Return object data in easily serializeable format"""
		return{
			'name': self.name,
			'description': self.description,
			'id': self.id
		}


engine = create_engine('sqlite:///gamecatalog.db')

Base.metadata.create_all(engine)