"""Initial database schema."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

def upgrade() -> None:
    """Create initial database schema."""

    # Users table
    op.create_table(
        'users',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('username', sa.String(128), nullable=False),
        sa.Column('password_hash', sa.String(255), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email'),
        sa.UniqueConstraint('username'),
    )
    op.create_index('idx_user_email_active', 'users', ['email', 'is_active'])
    op.create_index('idx_user_created_at', 'users', ['created_at'])
    op.create_index('idx_users_email', 'users', ['email'])
    op.create_index('idx_users_username', 'users', ['username'])
    op.create_index('idx_users_is_active', 'users', ['is_active'])

    # Investigations table
    op.create_table(
        'investigations',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('user_id', sa.String(36), nullable=False),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('status', sa.String(50), nullable=False, server_default='active'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('custom_metadata', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_investigation_user_status', 'investigations', ['user_id', 'status'])
    op.create_index('idx_investigation_created_at', 'investigations', ['created_at'])
    op.create_index('idx_investigations_user_id', 'investigations', ['user_id'])
    op.create_index('idx_investigations_status', 'investigations', ['status'])

    # Entities table
    op.create_table(
        'entities',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('investigation_id', sa.String(36), nullable=False),
        sa.Column('entity_type', sa.String(50), nullable=False),
        sa.Column('value', sa.String(512), nullable=False),
        sa.Column('risk_level', sa.String(50), nullable=False, server_default='INFO'),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('source', sa.String(128), nullable=True),
        sa.Column('first_seen', sa.DateTime(), nullable=True),
        sa.Column('last_seen', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('custom_metadata', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_entity_investigation_type', 'entities', ['investigation_id', 'entity_type'])
    op.create_index('idx_entity_value', 'entities', ['value'])
    op.create_index('idx_entity_risk_level', 'entities', ['risk_level'])
    op.create_index('idx_entity_created_at', 'entities', ['created_at'])

    # Relationships table
    op.create_table(
        'relationships',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('investigation_id', sa.String(36), nullable=False),
        sa.Column('source_id', sa.String(36), nullable=False),
        sa.Column('target_id', sa.String(36), nullable=False),
        sa.Column('relationship_type', sa.String(128), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('evidence', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('custom_metadata', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id']),
        sa.ForeignKeyConstraint(['source_id'], ['entities.id']),
        sa.ForeignKeyConstraint(['target_id'], ['entities.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_relationship_investigation', 'relationships', ['investigation_id'])
    op.create_index('idx_relationship_source_target', 'relationships', ['source_id', 'target_id'])
    op.create_index('idx_relationship_type', 'relationships', ['relationship_type'])
    op.create_index('idx_relationship_created_at', 'relationships', ['created_at'])

    # Threat Scores table
    op.create_table(
        'threat_scores',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('investigation_id', sa.String(36), nullable=False),
        sa.Column('entity_id', sa.String(36), nullable=False),
        sa.Column('overall_score', sa.Float(), nullable=False),
        sa.Column('threat_level', sa.String(50), nullable=False),
        sa.Column('malware_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('phishing_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('c2_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('breach_history_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('reputation_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('infrastructure_sharing_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('recency_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('credential_exposure_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('evidence', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='[]'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id']),
        sa.ForeignKeyConstraint(['entity_id'], ['entities.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_threat_score_investigation', 'threat_scores', ['investigation_id'])
    op.create_index('idx_threat_score_entity', 'threat_scores', ['entity_id'])
    op.create_index('idx_threat_score_overall', 'threat_scores', ['overall_score'])
    op.create_index('idx_threat_score_level', 'threat_scores', ['threat_level'])

    # Alerts table
    op.create_table(
        'alerts',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('investigation_id', sa.String(36), nullable=False),
        sa.Column('threat_score_id', sa.String(36), nullable=False),
        sa.Column('alert_type', sa.String(128), nullable=False),
        sa.Column('severity', sa.String(50), nullable=False),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('evidence', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('is_acknowledged', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('acknowledged_at', sa.DateTime(), nullable=True),
        sa.Column('acknowledged_by', sa.String(36), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id']),
        sa.ForeignKeyConstraint(['threat_score_id'], ['threat_scores.id']),
        sa.ForeignKeyConstraint(['acknowledged_by'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_alert_investigation', 'alerts', ['investigation_id'])
    op.create_index('idx_alert_type', 'alerts', ['alert_type'])
    op.create_index('idx_alert_severity', 'alerts', ['severity'])
    op.create_index('idx_alert_acknowledged', 'alerts', ['is_acknowledged'])
    op.create_index('idx_alert_created_at', 'alerts', ['created_at'])

    # Findings table
    op.create_table(
        'findings',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('investigation_id', sa.String(36), nullable=False),
        sa.Column('finding_type', sa.String(128), nullable=False),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(50), nullable=False),
        sa.Column('evidence', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('recommendations', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='[]'),
        sa.Column('status', sa.String(50), nullable=False, server_default='open'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_finding_investigation', 'findings', ['investigation_id'])
    op.create_index('idx_finding_severity', 'findings', ['severity'])
    op.create_index('idx_finding_status', 'findings', ['status'])

    # Investigation Snapshots table
    op.create_table(
        'investigation_snapshots',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('investigation_id', sa.String(36), nullable=False),
        sa.Column('entity_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('relationship_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('cluster_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('pattern_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('risk_distribution', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('graph_density', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('avg_node_degree', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_snapshot_investigation', 'investigation_snapshots', ['investigation_id'])
    op.create_index('idx_snapshot_created_at', 'investigation_snapshots', ['created_at'])

    # Sync Events table
    op.create_table(
        'sync_events',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('event_type', sa.String(50), nullable=False),
        sa.Column('entity_id', sa.String(36), nullable=True),
        sa.Column('investigation_id', sa.String(36), nullable=False),
        sa.Column('payload', postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column('synced_to_neo4j', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('sync_attempts', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_sync_attempt', sa.DateTime(), nullable=True),
        sa.Column('last_sync_error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('synced_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_sync_event_investigation', 'sync_events', ['investigation_id'])
    op.create_index('idx_sync_event_synced', 'sync_events', ['synced_to_neo4j'])
    op.create_index('idx_sync_event_created_at', 'sync_events', ['created_at'])
    op.create_index('idx_sync_event_type', 'sync_events', ['event_type'])

    # Sync Log table
    op.create_table(
        'sync_log',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('batch_id', sa.String(36), nullable=False),
        sa.Column('event_count', sa.Integer(), nullable=False),
        sa.Column('success_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('failure_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_sync_log_batch_id', 'sync_log', ['batch_id'])
    op.create_index('idx_sync_log_status', 'sync_log', ['status'])
    op.create_index('idx_sync_log_created_at', 'sync_log', ['created_at'])


def downgrade() -> None:
    """Drop all tables."""
    op.drop_table('sync_log')
    op.drop_table('sync_events')
    op.drop_table('investigation_snapshots')
    op.drop_table('findings')
    op.drop_table('alerts')
    op.drop_table('threat_scores')
    op.drop_table('relationships')
    op.drop_table('entities')
    op.drop_table('investigations')
    op.drop_table('users')
