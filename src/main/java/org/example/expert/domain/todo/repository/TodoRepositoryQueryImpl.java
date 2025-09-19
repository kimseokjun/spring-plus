package org.example.expert.domain.todo.repository;

import com.querydsl.core.types.Projections;
import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.jpa.impl.JPAQueryFactory;
import lombok.RequiredArgsConstructor;
import org.example.expert.domain.comment.entity.QComment;
import org.example.expert.domain.manager.entity.QManager;
import org.example.expert.domain.todo.dto.request.TodoSearchRequest;
import org.example.expert.domain.todo.dto.response.TodoSearchResponse;
import org.example.expert.domain.todo.entity.QTodo;
import org.example.expert.domain.todo.entity.Todo;
import org.example.expert.domain.user.entity.QUser;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@RequiredArgsConstructor
public class TodoRepositoryQueryImpl implements TodoRepositoryQuery {

    private final JPAQueryFactory jpaQueryFactory;

    //컴파일 시점에서 오류를 확인할 수 있다.
    @Override
    public Optional<Todo> findByIdWithUser(Long todoId) {
        QTodo todo = QTodo.todo;
        QUser user = QUser.user;

        Todo todo1 = jpaQueryFactory.selectFrom(todo)
                .leftJoin(todo.user, user).fetchJoin()
                .where(todo.id.eq(todoId))
                .fetchOne();
        //수현선생님의 도움을 받음
        return Optional.ofNullable(todo1);
    }

    @Override
    public Page<TodoSearchResponse> searchTodos(TodoSearchRequest todoSearchRequest, Pageable pageable) {
        QTodo todo = QTodo.todo;
        QUser user = QUser.user;
        QManager manager = QManager.manager;
        QComment comment = QComment.comment;

        List<TodoSearchResponse> results = jpaQueryFactory
                .select(Projections.constructor(TodoSearchResponse.class,
                        todo.title, todo.managers.size().longValue(), comment.countDistinct()))
                .from(todo)
                .leftJoin(todo.managers, manager)
                .leftJoin(todo.comments, comment)
                .where(
                        containsTitle(todoSearchRequest.keyword()),
                        betweenCreatedAt(todoSearchRequest.startDate(), todoSearchRequest.endDate()),
                        containsNickname(todoSearchRequest.nickname())
                ).fetch();

        return new PageImpl<>(results, pageable, results.size());
    }

    private BooleanExpression containsTitle(String keyword) {
        return StringUtils.hasText(keyword) ? QTodo.todo.title.containsIgnoreCase(keyword) : null;
    }

    private BooleanExpression betweenCreatedAt(LocalDateTime start, LocalDateTime end) {
        if (start != null && end != null) {
            return QTodo.todo.createdAt.between(start, end);
        }
        return null;
    }

    private BooleanExpression containsNickname(String nickname) {
        return StringUtils.hasText(nickname) ? QUser.user.nickname.containsIgnoreCase(nickname) : null;
    }
}
