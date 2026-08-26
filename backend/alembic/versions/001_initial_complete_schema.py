"""initial_complete_schema

Revision ID: 001_initial
Revises: 
Create Date: 2026-08-26 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '001_initial'
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table(
        'projects',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('name', sa.String(), nullable=False, index=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'))
    )

    op.create_table(
        'targets',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('project_id', sa.String(), sa.ForeignKey('projects.id', ondelete='SET NULL'), nullable=True, index=True),
        sa.Column('name', sa.String(), nullable=False, index=True),
        sa.Column('base_url', sa.String(), nullable=False, index=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'))
    )

    op.create_table(
        'scans',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('target_id', sa.String(), sa.ForeignKey('targets.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('status', sa.String(), default='QUEUED', index=True),
        sa.Column('scan_mode', sa.String(), default='Standard'),
        sa.Column('current_stage', sa.String(), default='INITIALIZING', index=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('progress', sa.Integer(), default=0),
        sa.Column('error_message', sa.Text(), nullable=True)
    )

    op.create_table(
        'endpoints',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('scan_id', sa.String(), sa.ForeignKey('scans.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('url', sa.String(), nullable=False, index=True),
        sa.Column('path', sa.String(), nullable=False, index=True),
        sa.Column('method', sa.String(), nullable=False, default='GET'),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('content_type', sa.String(), nullable=True),
        sa.Column('depth', sa.Integer(), default=0),
        sa.Column('discovered_from', sa.String(), nullable=True),
        sa.Column('is_api', sa.Boolean(), default=False),
        sa.Column('priority_score', sa.Float(), default=0.0)
    )

    op.create_table(
        'parameters',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('endpoint_id', sa.String(), sa.ForeignKey('endpoints.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('name', sa.String(), nullable=False, index=True),
        sa.Column('location', sa.String(), nullable=False, default='query'),
        sa.Column('value_type', sa.String(), nullable=True, default='string')
    )

    op.create_table(
        'subdomains',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('scan_id', sa.String(), sa.ForeignKey('scans.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('domain', sa.String(), nullable=False, index=True),
        sa.Column('ip_address', sa.String(), nullable=True),
        sa.Column('is_alive', sa.Boolean(), default=False)
    )

    op.create_table(
        'virtual_hosts',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('scan_id', sa.String(), sa.ForeignKey('scans.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('host', sa.String(), nullable=False, index=True),
        sa.Column('ip_address', sa.String(), nullable=True),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('is_active', sa.Boolean(), default=True)
    )

    op.create_table(
        'findings',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('scan_id', sa.String(), sa.ForeignKey('scans.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('endpoint_id', sa.String(), sa.ForeignKey('endpoints.id', ondelete='SET NULL'), nullable=True, index=True),
        sa.Column('parameter_id', sa.String(), sa.ForeignKey('parameters.id', ondelete='SET NULL'), nullable=True, index=True),
        sa.Column('vulnerability_type', sa.String(), nullable=False, index=True),
        sa.Column('severity', sa.String(), nullable=False, index=True),
        sa.Column('confidence', sa.String(), default='90%'),
        sa.Column('priority', sa.String(), default='P2', index=True),
        sa.Column('status', sa.String(), default='open', index=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('impact', sa.Text(), nullable=True),
        sa.Column('cwe', sa.String(), nullable=True),
        sa.Column('owasp_category', sa.String(), nullable=True),
        sa.Column('remediation', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'))
    )

    op.create_table(
        'evidence',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('finding_id', sa.String(), sa.ForeignKey('findings.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('evidence_type', sa.String(), nullable=True),
        sa.Column('baseline_summary', sa.Text(), nullable=True),
        sa.Column('test_summary', sa.Text(), nullable=True),
        sa.Column('analysis', sa.Text(), nullable=True),
        sa.Column('confidence', sa.String(), nullable=True, default='HIGH')
    )

    op.create_table(
        'retests',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('finding_id', sa.String(), sa.ForeignKey('findings.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('status', sa.String(), default='completed', index=True),
        sa.Column('result', sa.String(), default='VULNERABLE'),
        sa.Column('executed_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'))
    )

    op.create_table(
        'payload_items',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('category', sa.String(), nullable=False, index=True),
        sa.Column('payload', sa.Text(), nullable=False),
        sa.Column('indicator', sa.String(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_custom', sa.Boolean(), default=False),
        sa.Column('usage_count', sa.Integer(), default=0),
        sa.Column('success_count', sa.Integer(), default=0),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'))
    )

    op.create_table(
        'fuzz_results',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('scan_id', sa.String(), sa.ForeignKey('scans.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('endpoint_id', sa.String(), sa.ForeignKey('endpoints.id', ondelete='SET NULL'), nullable=True, index=True),
        sa.Column('parameter_id', sa.String(), sa.ForeignKey('parameters.id', ondelete='SET NULL'), nullable=True, index=True),
        sa.Column('test_id', sa.String(), nullable=True),
        sa.Column('category', sa.String(), nullable=False, index=True),
        sa.Column('payload', sa.Text(), nullable=False),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('response_time_ms', sa.Float(), default=0.0),
        sa.Column('anomaly_detected', sa.Boolean(), default=False, index=True),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('executed_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'))
    )

    op.create_table(
        'scan_logs',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('scan_id', sa.String(), sa.ForeignKey('scans.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('level', sa.String(), default='INFO'),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'))
    )

def downgrade() -> None:
    op.drop_table('scan_logs')
    op.drop_table('fuzz_results')
    op.drop_table('payload_items')
    op.drop_table('retests')
    op.drop_table('evidence')
    op.drop_table('findings')
    op.drop_table('virtual_hosts')
    op.drop_table('subdomains')
    op.drop_table('parameters')
    op.drop_table('endpoints')
    op.drop_table('scans')
    op.drop_table('targets')
    op.drop_table('projects')
