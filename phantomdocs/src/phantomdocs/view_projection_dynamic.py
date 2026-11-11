"""Opt-in read-only projection revalidation against current PhantomOrg.

The installed viewer still owns approved generation storage and review. The
host must use a pinned compatible viewer and keep per-request authorization.
"""

from phantomdocs.view_projection_revalidate import revalidate_catalog


def dynamic_projection_class(review):
    """Wrap the host's projection without changing administrative approval."""

    class DynamicProjection(review.PublishedProjection):
        def _visible(self):
            root = review.root_path(self.root)
            pointer = review.read_json(root / "active.json")
            if (
                not isinstance(pointer, dict)
                or set(pointer) != {"revision"}
                or not isinstance(pointer["revision"], str)
                or not review.HEX.fullmatch(pointer["revision"])
            ):
                raise ValueError("Invalid active projection pointer")
            generation = review.root_path(root / pointer["revision"])
            bundle = review.validate(review.read_json(generation / "approval.json"))
            if bundle["revision"] != pointer["revision"]:
                raise ValueError("Active projection revision mismatch")
            org = self.org_loader()
            directory = review.HumanDirectory(org)
            draft = review.prepare_like(self.snapshot_loader(), directory, bundle)
            catalog = revalidate_catalog(
                bundle,
                draft,
                directory.scope.policy["view_access"],
                org["policies"]["security_categories"],
                directory.authority_revision,
                org["organization"]["id"],
            )
            review.ProjectionCatalog(catalog)
            org_revision = review.revision(org)
            if review.revision(self.org_loader()) != org_revision:
                raise ValueError("Organization changed during catalog derivation")
            source_revision = review.revision(
                {
                    "draft_revision": review.revision(draft),
                    "organization_revision": org_revision,
                }
            )
            return generation, bundle, catalog, source_revision

    return DynamicProjection
