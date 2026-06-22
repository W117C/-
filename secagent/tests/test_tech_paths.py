"""Tests for tech-stack-aware path discovery."""
from __future__ import annotations

from secagent.core.tech_paths import paths_for_tech, known_tech_keywords


def test_wordpress_returns_wp_paths():
    paths = paths_for_tech(["WordPress", "PHP", "nginx"])
    assert any("wp-admin" in p for p in paths)
    assert any("wp-content" in p for p in paths)
    assert any("wp-login" in p for p in paths)


def test_drupal_returns_drupal_paths():
    paths = paths_for_tech(["Drupal", "PHP"])
    assert any("sites/default" in p for p in paths)
    assert any("user/" in p for p in paths)


def test_spring_returns_actuator_paths():
    paths = paths_for_tech(["Spring Boot", "Java"])
    assert any("actuator/health" in p for p in paths)
    assert any("actuator/env" in p for p in paths)


def test_nginx_returns_status():
    paths = paths_for_tech(["nginx"])
    assert any("nginx-status" in p for p in paths)


def test_multiple_techs_combined():
    paths = paths_for_tech(["WordPress", "nginx"])
    assert any("wp-admin" in p for p in paths)
    assert any("nginx-status" in p for p in paths)


def test_empty_tech_stack():
    assert paths_for_tech(None) == []
    assert paths_for_tech([]) == []


def test_case_insensitive():
    paths1 = paths_for_tech(["wordpress"])
    paths2 = paths_for_tech(["WORDPRESS"])
    paths3 = paths_for_tech(["WordPress"])
    assert paths1 == paths2 == paths3


def test_known_keywords():
    keywords = known_tech_keywords()
    assert "wordpress" in keywords
    assert "drupal" in keywords
    assert "nginx" in keywords
    assert len(keywords) >= 20


def test_no_duplicates():
    """Same tech shouldn't produce duplicate paths when matched multiple times."""
    paths = paths_for_tech(["WordPress", "WordPress", "WordPress"])
    assert len(paths) == len(set(paths))
