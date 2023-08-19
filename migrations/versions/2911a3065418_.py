"""empty message

Revision ID: 2911a3065418
Revises: 1e0b777cf254
Create Date: 2023-08-15 22:59:34.820435

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2911a3065418'
down_revision = '1e0b777cf254'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('user_name', sa.String(length=120), nullable=False))
        batch_op.add_column(sa.Column('first_name', sa.String(length=120), nullable=False))
        batch_op.add_column(sa.Column('last_name', sa.String(length=120), nullable=False))
        batch_op.add_column(sa.Column('token', sa.String(length=80), nullable=False))
        batch_op.create_unique_constraint(None, ['user_name'])
        batch_op.create_unique_constraint(None, ['token'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='unique')
        batch_op.drop_constraint(None, type_='unique')
        batch_op.drop_column('token')
        batch_op.drop_column('last_name')
        batch_op.drop_column('first_name')
        batch_op.drop_column('user_name')

    # ### end Alembic commands ###
