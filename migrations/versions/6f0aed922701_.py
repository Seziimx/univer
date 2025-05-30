"""empty message

Revision ID: 6f0aed922701
Revises: 305367d373c0
Create Date: 2025-04-15 10:57:45.907292

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6f0aed922701'
down_revision = '305367d373c0'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('zayavka', schema=None) as batch_op:
        batch_op.add_column(sa.Column('urgent', sa.Boolean(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('zayavka', schema=None) as batch_op:
        batch_op.drop_column('urgent')

    # ### end Alembic commands ###
