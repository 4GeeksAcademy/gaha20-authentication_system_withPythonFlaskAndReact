"""empty message

Revision ID: 145112ede937
Revises: 2911a3065418
Create Date: 2023-08-19 17:29:05.725972

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '145112ede937'
down_revision = '2911a3065418'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('salt', sa.String(length=80), nullable=False))
        batch_op.drop_constraint('user_token_key', type_='unique')
        batch_op.create_unique_constraint(None, ['salt'])
        batch_op.drop_column('token')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('token', sa.VARCHAR(length=80), autoincrement=False, nullable=False))
        batch_op.drop_constraint(None, type_='unique')
        batch_op.create_unique_constraint('user_token_key', ['token'])
        batch_op.drop_column('salt')

    # ### end Alembic commands ###