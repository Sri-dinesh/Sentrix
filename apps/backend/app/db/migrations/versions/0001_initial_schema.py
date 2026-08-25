"""initial schema

Revision ID: 0001_initial_schema
Revises: 
Create Date: 2026-08-25 21:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '0001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. users table
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('clerk_user_id', sa.String(), nullable=False),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('role', sa.String(), nullable=False, server_default='analyst'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
    )
    op.create_index('ix_users_clerk_user_id', 'users', ['clerk_user_id'], unique=True)
    op.create_index('ix_users_email', 'users', ['email'], unique=True)

    # 2. flows table
    op.create_table(
        'flows',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('captured_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('src_ip', sa.String(), nullable=False),
        sa.Column('dst_ip', sa.String(), nullable=False),
        sa.Column('src_port', sa.Integer(), nullable=False),
        sa.Column('dst_port', sa.Integer(), nullable=False),
        sa.Column('protocol', sa.String(), nullable=False),
        sa.Column('packet_count', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('byte_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('duration', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('raw_features', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
    )
    op.create_index('ix_flows_captured_at', 'flows', ['captured_at'])
    op.create_index('ix_flows_src_ip', 'flows', ['src_ip'])
    op.create_index('ix_flows_dst_ip', 'flows', ['dst_ip'])
    op.create_index('ix_flows_src_ip_captured_at', 'flows', ['src_ip', 'captured_at'])

    # 3. detections table
    op.create_table(
        'detections',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('flow_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('flows.id', ondelete='CASCADE'), nullable=False),
        sa.Column('anomaly_score', sa.Float(), nullable=False),
        sa.Column('is_anomalous', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('attack_type', sa.String(), nullable=True),
        sa.Column('classifier_margin', sa.Float(), nullable=True),
        sa.Column('drift_score', sa.Float(), nullable=True),
        sa.Column('confidence_score', sa.Float(), nullable=False),
        sa.Column('confidence_breakdown', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.CheckConstraint('confidence_score >= 0.0 AND confidence_score <= 1.0', name='check_confidence_score_range'),
    )
    op.create_index('ix_detections_flow_id', 'detections', ['flow_id'])
    op.create_index('ix_detections_confidence_score', 'detections', ['confidence_score'])

    # 4. mitre_techniques table
    op.create_table(
        'mitre_techniques',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('tactic', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
    )

    # 5. incidents table
    op.create_table(
        'incidents',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('detection_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('detections.id', ondelete='CASCADE'), unique=True, nullable=False),
        sa.Column('status', sa.String(), nullable=False, server_default='open'),
        sa.Column('action_taken', sa.String(), nullable=False, server_default='MONITOR'),
        sa.Column('mitre_technique_id', sa.String(), sa.ForeignKey('mitre_techniques.id', ondelete='SET NULL'), nullable=True),
        sa.Column('resolved_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("status IN ('open', 'investigating', 'contained', 'resolved', 'false_positive')", name='check_incident_status_valid'),
    )
    op.create_index('ix_incidents_status', 'incidents', ['status'])

    # 6. playbooks table
    op.create_table(
        'playbooks',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('incident_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('incidents.id', ondelete='CASCADE'), unique=True, nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('generated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
    )

    # 7. model_versions table
    op.create_table(
        'model_versions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('component', sa.String(), nullable=False),
        sa.Column('version_tag', sa.String(), nullable=False),
        sa.Column('storage_path', sa.String(), nullable=False),
        sa.Column('metrics', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('trained_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
    )
    op.create_index('ix_model_versions_component', 'model_versions', ['component'])

    # 8. drift_events table
    op.create_table(
        'drift_events',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('drift_score', sa.Float(), nullable=False),
        sa.Column('triggered_retrain', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
    )

    # 9. settings table
    op.create_table(
        'settings',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('confidence_weight_anomaly', sa.Float(), nullable=False, server_default='0.4'),
        sa.Column('confidence_weight_classifier', sa.Float(), nullable=False, server_default='0.4'),
        sa.Column('confidence_weight_drift', sa.Float(), nullable=False, server_default='0.2'),
        sa.Column('tier_high_threshold', sa.Float(), nullable=False, server_default='0.85'),
        sa.Column('tier_medium_threshold', sa.Float(), nullable=False, server_default='0.50'),
        sa.Column('anomaly_base_threshold', sa.Float(), nullable=False, server_default='0.05'),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
    )


def downgrade() -> None:
    op.drop_table('settings')
    op.drop_table('drift_events')
    op.drop_index('ix_model_versions_component', table_name='model_versions')
    op.drop_table('model_versions')
    op.drop_table('playbooks')
    op.drop_index('ix_incidents_status', table_name='incidents')
    op.drop_table('incidents')
    op.drop_table('mitre_techniques')
    op.drop_index('ix_detections_confidence_score', table_name='detections')
    op.drop_index('ix_detections_flow_id', table_name='detections')
    op.drop_table('detections')
    op.drop_index('ix_flows_src_ip_captured_at', table_name='flows')
    op.drop_index('ix_flows_dst_ip', table_name='flows')
    op.drop_index('ix_flows_src_ip', table_name='flows')
    op.drop_index('ix_flows_captured_at', table_name='flows')
    op.drop_table('flows')
    op.drop_index('ix_users_email', table_name='users')
    op.drop_index('ix_users_clerk_user_id', table_name='users')
    op.drop_table('users')
