"""Add profile fields to User model

Revision ID: 842bab39484d
Revises: e92cd2dd6b91
Create Date: 2025-04-15 03:47:55.086090

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '842bab39484d'
down_revision = 'e92cd2dd6b91'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('full_name', sa.String(length=150), nullable=True))
        batch_op.add_column(sa.Column('faculty', sa.String(length=150), nullable=True))
        batch_op.add_column(sa.Column('position', sa.String(length=150), nullable=True))
        batch_op.add_column(sa.Column('photo', sa.String(length=200), nullable=True))
        batch_op.alter_column('username',
               existing_type=sa.VARCHAR(length=150),
               nullable=False)
        batch_op.alter_column('email',
               existing_type=sa.VARCHAR(length=150),
               nullable=False)
        batch_op.alter_column('password',
               existing_type=sa.VARCHAR(length=255),
               nullable=False)
        batch_op.alter_column('role',
               existing_type=sa.VARCHAR(length=20),
               nullable=False)
        batch_op.drop_column('plain_password')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('plain_password', sa.VARCHAR(length=128), nullable=True))
        batch_op.alter_column('role',
               existing_type=sa.VARCHAR(length=20),
               nullable=True)
        batch_op.alter_column('password',
               existing_type=sa.VARCHAR(length=255),
               nullable=True)
        batch_op.alter_column('email',
               existing_type=sa.VARCHAR(length=150),
               nullable=True)
        batch_op.alter_column('username',
               existing_type=sa.VARCHAR(length=150),
               nullable=True)
        batch_op.drop_column('photo')
        batch_op.drop_column('position')
        batch_op.drop_column('faculty')
        batch_op.drop_column('full_name')

    # ### end Alembic commands ###
