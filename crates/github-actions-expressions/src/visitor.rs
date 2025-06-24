//! Visitor traits for traversing expressions.
//!
//! The `Visitor` trait provides a flexible way to traverse and analyze
//! GitHub Actions expressions. It follows the visitor pattern, allowing
//! you to define custom behavior for each expression type while automatically
//! handling the recursive traversal of sub-expressions.
//!
//! ## Example Usage
//!
//! ```rust
//! use github_actions_expressions::{Expr, visitor::{Visitor, Visitable}, Origin};
//! use github_actions_expressions::Literal;
//!
//! // Create a custom visitor that finds all string literals
//! struct StringFinder {
//!     strings: Vec<String>,
//! }
//!
//! impl StringFinder {
//!     fn new() -> Self {
//!         Self { strings: Vec::new() }
//!     }
//! }
//!
//! impl<'src> Visitor<'src> for StringFinder {
//!     fn visit_literal(&mut self, origin: &Origin<'src>, lit: &Literal<'src>) {
//!         if let Literal::String(s) = lit {
//!             self.strings.push(s.to_string());
//!         }
//!         self.super_literal(origin, lit);
//!     }
//! }
//!
//! // Parse an expression and find all strings
//! let expr = Expr::parse("format('Hello, {0}!', github.actor)").unwrap();
//! let mut finder = StringFinder::new();
//! expr.accept(&mut finder);
//!
//! assert_eq!(finder.strings, vec!["Hello, {0}!"]);
//! ```

use crate::{
    BinOp, Expr, Function, Identifier, Literal, Origin, SpannedExpr, UnOp, context::Context,
};

/// A visitor trait for traversing GitHub Actions expressions.
///
/// This trait provides methods for visiting each variant of `Expr` and its
/// sub-components. The default implementations call the corresponding "super"
/// methods, which handle the recursive traversal automatically.
///
/// Users can override specific visit methods to customize behavior for
/// particular expression types while still benefiting from automatic
/// traversal of sub-expressions.
///
/// All visitor methods receive an `&Origin<'src>` parameter containing the
/// source location and raw text of the expression being visited.
pub trait Visitor<'src> {
    /// Visit an expression.
    ///
    /// This is the main entry point for visiting expressions.
    fn visit_expr(&mut self, origin: &Origin<'src>, expr: &Expr<'src>) {
        self.super_expr(origin, expr);
    }

    /// Visit a literal value.
    fn visit_literal(&mut self, origin: &Origin<'src>, lit: &Literal<'src>) {
        self.super_literal(origin, lit);
    }

    /// Visit a star pattern (`*`).
    fn visit_star(&mut self, origin: &Origin<'src>) {
        self.super_star(origin);
    }

    /// Visit a function call.
    fn visit_call(
        &mut self,
        origin: &Origin<'src>,
        func: &Function<'src>,
        args: &[&SpannedExpr<'src>],
    ) {
        self.super_call(origin, func, args);
    }

    /// Visit an identifier.
    fn visit_identifier(&mut self, origin: &Origin<'src>, ident: &Identifier<'src>) {
        self.super_identifier(origin, ident);
    }

    /// Visit an index expression.
    fn visit_index(&mut self, origin: &Origin<'src>, expr: &SpannedExpr<'src>) {
        self.super_index(origin, expr);
    }

    /// Visit a context reference.
    fn visit_context(&mut self, origin: &Origin<'src>, ctx: &Context<'src>) {
        self.super_context(origin, ctx);
    }

    /// Visit a binary operation.
    fn visit_binop(
        &mut self,
        origin: &Origin<'src>,
        lhs: &SpannedExpr<'src>,
        op: &BinOp,
        rhs: &SpannedExpr<'src>,
    ) {
        self.super_binop(origin, lhs, op, rhs);
    }

    /// Visit a unary operation.
    fn visit_unop(&mut self, origin: &Origin<'src>, op: &UnOp, expr: &SpannedExpr<'src>) {
        self.super_unop(origin, op, expr);
    }

    // Super methods handle the default traversal logic and are not meant to be overridden.

    /// Default traversal for expressions.
    ///
    /// Dispatches to the appropriate visit method based on the expression variant.
    fn super_expr(&mut self, origin: &Origin<'src>, expr: &Expr<'src>) {
        match expr {
            Expr::Literal(lit) => self.visit_literal(origin, lit),
            Expr::Star => self.visit_star(origin),
            Expr::Call { func, args } => {
                self.visit_call(origin, func, &args.iter().collect::<Vec<_>>());
            }
            Expr::Identifier(ident) => self.visit_identifier(origin, ident),
            Expr::Index(expr) => self.visit_index(origin, expr),
            Expr::Context(ctx) => self.visit_context(origin, ctx),
            Expr::BinOp { lhs, op, rhs } => self.visit_binop(origin, lhs, op, rhs),
            Expr::UnOp { op, expr } => self.visit_unop(origin, op, expr),
        }
    }

    /// Terminal for `visit_literal`.
    fn super_literal(&mut self, _origin: &Origin<'src>, _lit: &Literal<'src>) {}

    /// Terminal for `visit_star`.
    fn super_star(&mut self, _origin: &Origin<'src>) {}

    /// Default traversal for function calls.
    ///
    /// Visits all arguments.
    fn super_call(
        &mut self,
        _origin: &Origin<'src>,
        _func: &Function<'src>,
        args: &[&SpannedExpr<'src>],
    ) {
        for arg in args {
            self.visit_expr(&arg.origin, &arg.inner);
        }
    }

    /// Terminal for `visit_identifier`.
    fn super_identifier(&mut self, _origin: &Origin<'src>, _ident: &Identifier<'src>) {}

    /// Default traversal for index expressions.
    ///
    /// Visits the inner expression.
    fn super_index(&mut self, _origin: &Origin<'src>, expr: &SpannedExpr<'src>) {
        self.visit_expr(&expr.origin, &expr.inner);
    }

    /// Default traversal for context references.
    ///
    /// Visits all parts of the context.
    fn super_context(&mut self, _origin: &Origin<'src>, ctx: &Context<'src>) {
        for part in &ctx.parts {
            self.visit_expr(&part.origin, &part.inner);
        }
    }

    /// Default traversal for binary operations.
    ///
    /// Visits both operands.
    fn super_binop(
        &mut self,
        _origin: &Origin<'src>,
        lhs: &SpannedExpr<'src>,
        _op: &BinOp,
        rhs: &SpannedExpr<'src>,
    ) {
        self.visit_expr(&lhs.origin, &lhs.inner);
        self.visit_expr(&rhs.origin, &rhs.inner);
    }

    /// Default traversal for unary operations.
    ///
    /// Visits the operand.
    fn super_unop(&mut self, _origin: &Origin<'src>, _op: &UnOp, expr: &SpannedExpr<'src>) {
        self.visit_expr(&expr.origin, &expr.inner);
    }
}

/// Extension trait to add visitor functionality to expressions.
pub trait Visitable<'src> {
    /// Accept a visitor and traverse this expression.
    fn accept<V: Visitor<'src>>(&self, visitor: &mut V);
}

impl<'src> Visitable<'src> for SpannedExpr<'src> {
    fn accept<V: Visitor<'src>>(&self, visitor: &mut V) {
        visitor.visit_expr(&self.origin, &self.inner);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Expr;

    /// Example visitor that counts different types of expressions.
    #[derive(Default)]
    struct ExpressionCounter {
        literals: usize,
        identifiers: usize,
        function_calls: usize,
        binary_ops: usize,
        unary_ops: usize,
        contexts: usize,
        stars: usize,
        indices: usize,
    }

    impl<'src> Visitor<'src> for ExpressionCounter {
        fn visit_literal(&mut self, origin: &Origin<'src>, lit: &Literal<'src>) {
            self.literals += 1;
            self.super_literal(origin, lit);
        }

        fn visit_identifier(&mut self, origin: &Origin<'src>, ident: &Identifier<'src>) {
            self.identifiers += 1;
            self.super_identifier(origin, ident);
        }

        fn visit_call(
            &mut self,
            origin: &Origin<'src>,
            func: &Function<'src>,
            args: &[&SpannedExpr<'src>],
        ) {
            self.function_calls += 1;
            self.super_call(origin, func, args);
        }

        fn visit_binop(
            &mut self,
            origin: &Origin<'src>,
            lhs: &SpannedExpr<'src>,
            op: &BinOp,
            rhs: &SpannedExpr<'src>,
        ) {
            self.binary_ops += 1;
            self.super_binop(origin, lhs, op, rhs);
        }

        fn visit_unop(&mut self, origin: &Origin<'src>, op: &UnOp, expr: &SpannedExpr<'src>) {
            self.unary_ops += 1;
            self.super_unop(origin, op, expr);
        }

        fn visit_context(&mut self, origin: &Origin<'src>, ctx: &Context<'src>) {
            self.contexts += 1;
            self.super_context(origin, ctx);
        }

        fn visit_star(&mut self, origin: &Origin<'src>) {
            self.stars += 1;
            self.super_star(origin);
        }

        fn visit_index(&mut self, origin: &Origin<'src>, expr: &SpannedExpr<'src>) {
            self.indices += 1;
            self.super_index(origin, expr);
        }
    }

    #[test]
    fn test_visitor_counting() {
        let expr = Expr::parse("foo.bar[1] && !baz || format('hello', github.actor)").unwrap();
        let mut counter = ExpressionCounter::default();
        expr.accept(&mut counter);

        // The expression contains:
        // - 2 literals: 1, 'hello'
        // - 5 identifiers: foo, bar, baz, github, actor
        // - 1 function call: format
        // - 2 binary ops: &&, ||
        // - 1 unary op: !
        // - 3 contexts: foo.bar[1], baz, github.actor (single identifiers are also contexts)
        // - 1 index: [1]
        assert_eq!(counter.literals, 2);
        assert_eq!(counter.identifiers, 5);
        assert_eq!(counter.function_calls, 1);
        assert_eq!(counter.binary_ops, 2);
        assert_eq!(counter.unary_ops, 1);
        assert_eq!(counter.contexts, 3);
        assert_eq!(counter.indices, 1);
    }

    /// Example visitor that counts context references.
    #[derive(Default)]
    struct ContextCounter {
        contexts: usize,
    }

    impl<'src> Visitor<'src> for ContextCounter {
        fn visit_context(&mut self, origin: &Origin<'src>, ctx: &Context<'src>) {
            self.contexts += 1;
            self.super_context(origin, ctx);
        }
    }

    #[test]
    fn test_context_counter() {
        let expr = Expr::parse("foo.bar && github.event.name || inputs.value").unwrap();
        let mut counter = ContextCounter::default();
        expr.accept(&mut counter);

        assert_eq!(counter.contexts, 3);
        // The expression contains three contexts: foo.bar, github.event.name, inputs.value
    }

    #[test]
    fn test_visitor_receives_origins() {
        /// A visitor that collects origins of visited expressions
        #[derive(Default)]
        struct OriginCollector<'src> {
            origins: Vec<Origin<'src>>,
        }

        impl<'src> Visitor<'src> for OriginCollector<'src> {
            fn visit_literal(&mut self, origin: &Origin<'src>, _lit: &Literal<'src>) {
                self.origins.push(*origin);
                self.super_literal(origin, _lit);
            }
        }

        let expr = Expr::parse("foo.bar && 'hello'").unwrap();
        let mut collector = OriginCollector::default();
        expr.accept(&mut collector);

        assert_eq!(collector.origins[0], Origin::new(11..18, "'hello'"))
    }

    #[test]
    fn test_visitor_receives_individual_origins() {
        /// A visitor that collects origins and expression types
        #[derive(Default)]
        struct DetailedOriginCollector {
            binop_origins: Vec<(String, String, String)>, // (overall, lhs, rhs)
            unop_origins: Vec<(String, String)>,          // (overall, expr)
            call_origins: Vec<(String, Vec<String>)>,     // (overall, args)
            index_origins: Vec<(String, String)>,         // (overall, expr)
        }

        impl<'src> Visitor<'src> for DetailedOriginCollector {
            fn visit_binop(
                &mut self,
                origin: &Origin<'src>,
                lhs: &SpannedExpr<'src>,
                _op: &BinOp,
                rhs: &SpannedExpr<'src>,
            ) {
                self.binop_origins.push((
                    origin.raw.to_string(),
                    lhs.origin.raw.to_string(),
                    rhs.origin.raw.to_string(),
                ));
                self.super_binop(origin, lhs, _op, rhs);
            }

            fn visit_unop(&mut self, origin: &Origin<'src>, _op: &UnOp, expr: &SpannedExpr<'src>) {
                self.unop_origins
                    .push((origin.raw.to_string(), expr.origin.raw.to_string()));
                self.super_unop(origin, _op, expr);
            }

            fn visit_call(
                &mut self,
                origin: &Origin<'src>,
                _func: &Function<'src>,
                args: &[&SpannedExpr<'src>],
            ) {
                let arg_origins: Vec<String> =
                    args.iter().map(|arg| arg.origin.raw.to_string()).collect();
                self.call_origins
                    .push((origin.raw.to_string(), arg_origins));
                self.super_call(origin, _func, args);
            }

            fn visit_index(&mut self, origin: &Origin<'src>, expr: &SpannedExpr<'src>) {
                self.index_origins
                    .push((origin.raw.to_string(), expr.origin.raw.to_string()));
                self.super_index(origin, expr);
            }
        }

        let expr = Expr::parse("foo.bar[1] && !baz || format('hello', github.actor)").unwrap();
        let mut collector = DetailedOriginCollector::default();
        expr.accept(&mut collector);

        // Verify we collected the expected number of operations
        assert_eq!(
            collector.binop_origins.len(),
            2,
            "Should have 2 binary operations (|| and &&)"
        );
        assert_eq!(
            collector.unop_origins.len(),
            1,
            "Should have 1 unary operation (!)"
        );
        assert_eq!(
            collector.call_origins.len(),
            1,
            "Should have 1 function call (format)"
        );
        assert_eq!(
            collector.index_origins.len(),
            1,
            "Should have 1 index operation ([1])"
        );

        // Test binary operations - verify individual origins are meaningful
        let or_binop = &collector.binop_origins[0]; // Top-level ||
        let and_binop = &collector.binop_origins[1]; // && operation

        // The || operation should span the entire expression
        assert!(
            or_binop.0.contains("&&") && or_binop.0.contains("||") && or_binop.0.contains("format")
        );
        // LHS should be the && part
        assert!(or_binop.1.contains("&&") && !or_binop.1.contains("||"));
        // RHS should be the format call
        assert!(or_binop.2.contains("format") && !or_binop.2.contains("&&"));

        // The && operation
        assert!(and_binop.0.contains("&&") && !and_binop.0.contains("||"));
        assert!(and_binop.1.contains("foo.bar[1]"));
        assert!(and_binop.2.contains("!baz"));

        // Test unary operation
        let unop = &collector.unop_origins[0];
        assert_eq!(unop.0, "!baz", "Unary operation should be '!baz'");
        assert_eq!(unop.1, "baz", "Unary operand should be 'baz'");

        // Test function call
        let call = &collector.call_origins[0];
        assert!(
            call.0.contains("format"),
            "Call origin should contain 'format'"
        );
        assert_eq!(call.1.len(), 2, "Should have 2 arguments");
        assert_eq!(call.1[0], "'hello'", "First arg should be 'hello'");
        assert_eq!(
            call.1[1], "github.actor",
            "Second arg should be 'github.actor'"
        );

        // Test index operation
        let index = &collector.index_origins[0];
        assert_eq!(index.0, "[1]", "Index operation should be '[1]'");
        assert_eq!(index.1, "1", "Index expression should be '1'");
    }
}
