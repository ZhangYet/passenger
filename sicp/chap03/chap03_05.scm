(define (stream-car stream) (car stream))
(define (stream-cdr stream) (force (cdr stream)))

(define (stream-ref s n)
  (if (= n 0)
      (stream-car s)
      (stream-ref (stream-cdr s) (- n 1))))

(define-syntax cons-stream
  (syntax-rules ()
    ((cons-stream a b)
     (cons a (delay b)))))

(define stream-null? null?)
(define the-empty-stream '())

(define (stream-map proc . argstreams)
  (if (stream-null? (car argstreams))
      the-empty-stream
      (cons-stream
       (apply proc (map stream-car argstreams))
       (apply stream-map (cons proc (map stream-cdr argstreams))))))

(define (stream-for-each proc s)
  (if (stream-null? s)
      'done
      (begin (proc (stream-car s))
	     (stream-for-each proc (stream-cdr s)))))

(define (stream-filter pred stream)
  (cond ((stream-null? stream) the-empty-stream)
	((pred (stream-car stream))
	 (cons-stream (stream-car stream)
		      (stream-filter pred (stream-cdr stream))))
	(else (stream-filter pred (stream-cdr stream)))))

(define (stream-enumerate-interval low high)
  (if (> low high)
      the-empty-stream
      (cons-stream
       low
       (stream-enumerate-interval (+ low 1) high))))

(define (display-line x)
  (newline)
  (display x))

(define (display-stream s)
  (stream-for-each display-line s))

;; (define s (stream-enumerate-interval 1 100))
;; (display-stream s)


;; 3.51
(define (show x)
  (display-line x)
  x)

(define x (stream-map show (stream-enumerate-interval 0 10))) ;; output 0

(stream-ref x 5) ;; output 1-5
(stream-ref x 7) ;; only output 6-7


;; 这正是 3.51 要揭示的核心：
;; - 流的头部是立即求值的——cons-stream 展开成 (cons a (delay b))，a 在构造时就求值，所以定义 x 时 (show 0) 立即执行、打印 0。
;; - 尾部是惰性的——stream-ref x 5 按需逐个 force，因此才依次打印 1~5。
;; - 记忆化——stream-ref x 7 时 0~5 的 promise 已经算过并缓存，force 不再执行 show，只有 6、7 是新算的。
;; 建议注释补一句
;; (define x ...) 打印 0，这样答案才完整。
