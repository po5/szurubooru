import os
from datetime import datetime, timedelta
from typing import Dict, Optional

from szurubooru import config, rest
from szurubooru.func import auth, posts, users, util

@rest.routes.get("/info/?")
def get_info(ctx: rest.Context, _params: Dict[str, str] = {}) -> rest.Response:
    ret = {
        "postCount": posts.get_post_count(),
        "serverTime": datetime.utcnow(),
        "config": {
            "name": config.config["name"],
            "userNameRegex": config.config["user_name_regex"],
            "passwordRegex": config.config["password_regex"],
            "tagNameRegex": config.config["tag_name_regex"],
            "tagCategoryNameRegex": config.config["tag_category_name_regex"],
            "defaultUserRank": config.config["default_rank"],
            "enableSafety": config.config["enable_safety"],
            "contactEmail": config.config["contact_email"],
            "canSendMails": bool(config.config["smtp"]["host"]),
            "privileges": util.snake_case_to_lower_camel_case_keys(
                config.config["privileges"]
            ),
        },
    }
    return ret
