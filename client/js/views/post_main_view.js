"use strict";

const iosCorrectedInnerHeight = require("@formfunfunction/inner-height");
const {iframeResizer} = require("iframe-resizer");
const router = require("../router.js");
const views = require("../util/views.js");
const uri = require("../util/uri.js");
const misc = require("../util/misc.js");
const keyboard = require("../util/keyboard.js");
const PostContentControl = require("../controls/post_content_control.js");
const PostNotesOverlayControl = require("../controls/post_notes_overlay_control.js");
const PostReadonlySidebarControl = require("../controls/post_readonly_sidebar_control.js");
const PostEditSidebarControl = require("../controls/post_edit_sidebar_control.js");
const PoolNavigatorListControl = require("../controls/pool_navigator_list_control.js");
//const CommentControl = require("../controls/comment_control.js");
//const CommentListControl = require("../controls/comment_list_control.js");

const template = views.getTemplate("post-main");

class PostMainView {
    constructor(ctx) {
        this._hostNode = document.getElementById("content-holder");

        const sourceNode = template(ctx);
        const postContainerNode = sourceNode.querySelector(".post-container");
        const sidebarNode = sourceNode.querySelector(".sidebar");
        views.replaceContent(this._hostNode, sourceNode);
        views.syncScrollPosition();

        const topNavigationNode =
            document.body.querySelector("#top-navigation");

        const contentNode =
            document.querySelector(".post-view > .content");

        this._postContentControl = new PostContentControl(
            postContainerNode,
            ctx.post,
            () => {
                const margin = sidebarNode.getBoundingClientRect().left;

                return [
                    postContainerNode.getBoundingClientRect().width,
                    iosCorrectedInnerHeight() -
                        topNavigationNode.getBoundingClientRect().height -
                        margin * 2,
                ];
            },
            contentNode
        );

        this._postNotesOverlayControl = new PostNotesOverlayControl(
            postContainerNode.querySelector(".post-overlay"),
            ctx.post
        );

        if (ctx.post.type === "video" || ctx.post.type === "flash") {
            this._postContentControl.disableOverlay();
        }

        this._installSidebar(ctx);
        this._installComments(ctx);
        this._installPoolNavigators(ctx.poolPostsNearby);
        this.postDescription = document.getElementById("post-description");

        const showPreviousImage = () => {
            if (ctx.prevPostId) {
                if (ctx.editMode) {
                    router.show(
                        ctx.getPostEditUrl(ctx.prevPostId, ctx.parameters)
                    );
                } else {
                    router.show(
                        ctx.getPostUrl(ctx.prevPostId, ctx.parameters)
                    );
                }
            }
        };

        const showNextImage = () => {
            if (ctx.nextPostId) {
                if (ctx.editMode) {
                    router.show(
                        ctx.getPostEditUrl(ctx.nextPostId, ctx.parameters)
                    );
                } else {
                    router.show(
                        ctx.getPostUrl(ctx.nextPostId, ctx.parameters)
                    );
                }
            }
        };

        keyboard.bind("e", () => {
            if (ctx.editMode) {
                router.show(uri.formatClientLink("post", ctx.post.id));
            } else {
                router.show(uri.formatClientLink("post", ctx.post.id, "edit"));
            }
        });
        keyboard.bind(["a", "left"], showPreviousImage);
        keyboard.bind(["d", "right"], showNextImage);
        keyboard.bind("del", (e) => {
            if (ctx.editMode) {
                this.sidebarControl._evtDeleteClick(e);
            }
        });
    }

    _installSidebar(ctx) {
        const sidebarContainerNode = document.querySelector(
            "#content-holder .sidebar-container"
        );

        if (ctx.editMode) {
            this.sidebarControl = new PostEditSidebarControl(
                sidebarContainerNode,
                ctx.post,
                this._postContentControl,
                this._postNotesOverlayControl
            );
        } else {
            this.sidebarControl = new PostReadonlySidebarControl(
                sidebarContainerNode,
                ctx.post,
                this._postContentControl
            );
        }
    }

    _installPoolNavigators(poolPostsNearby) {
        const poolNavigatorsContainerNode = document.querySelector(
            "#content-holder .pool-navigators-container"
        );
        if (!poolNavigatorsContainerNode) {
            return;
        }

        this.poolNavigatorsControl = new PoolNavigatorListControl(
            poolNavigatorsContainerNode,
            poolPostsNearby,
        );
    }

    _installComments(ctx) {
        const commentsContainerNode = document.querySelector(
            "#content-holder .comments-container"
        );
        if (!commentsContainerNode) {
            return;
        }

        const commentsIframe = document.createElement("iframe");
        commentsIframe.classList.add("comments-iframe");
        commentsIframe.src = `/booru/item/${ctx.post.id}/comments?darktheme=${document.body.classList.contains("darktheme") && "1" || ""}`;
        commentsIframe.style.height = "115px";
        views.replaceContent(commentsContainerNode, commentsIframe);
        iframeResizer({
            autoResize: true,
            sizeHeight: true,
            sizeWidth: false,
            scrolling: false
        }, ".comments-iframe");
    }
}

module.exports = PostMainView;
