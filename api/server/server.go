package server

import (
	"github.com/Docker69/NFTPawnShopSmartContract/api/server/auth"
	"github.com/Docker69/NFTPawnShopSmartContract/api/server/config"
	"github.com/Docker69/NFTPawnShopSmartContract/api/server/controller"
	"github.com/Docker69/NFTPawnShopSmartContract/api/server/model"
	"github.com/Docker69/NFTPawnShopSmartContract/api/server/service"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
)

type Server struct {
	router     *gin.Engine
	connection *config.Connection
	database   *mongo.Database
	tokenMaker auth.Maker
	env        *config.Env
	redis      *config.RedisClient
}

func NewServer(con *config.Connection, env *config.Env) (*Server, error) {
	database := con.GetDatabase(env.DatabaseName)
	tokenMaker, err := auth.NewPasetoMaker(env.SymmetricKey)
	if err != nil {
		return nil, err
	}
	redisClient := config.NewRedisClient(env.RedisHost)
	server := Server{
		connection: con,
		database:   database,
		tokenMaker: tokenMaker,
		env:        env,
		redis:      redisClient,
	}
	server.setupRouter()
	return &server, nil
}

func (s *Server) setupRouter() {
	// authMiddleware := middleware.NewAuthMiddleware(s.tokenMaker)
	router := gin.Default()
	router.Use(cors.Default())
	// authRouter := router.Group("/").Use(authMiddleware)

	userModel := model.NewUsers(s.database)
	userService := service.NewUserService(userModel)
	userController := controller.NewUserController(userService, s.redis)
	// authRouter.GET("/users/:address", userController.FindOne)
	router.GET("/users/:address", userController.FindOneByAddress)
	router.POST("/users", userController.InsertOne)

	pawnModel := model.NewPawns(s.database)
	pawnService := service.NewPawn(pawnModel)
	pawnController := controller.NewPawnController(pawnService)
	router.GET("/users/:address/pawns", pawnController.FindAllByCreatorAddress)
	router.POST("/pawns", pawnController.InsertOne)
	router.PATCH("/pawns/:id", pawnController.UpdateById)
	router.GET("/pawns/:id", pawnController.FindOne)
	router.GET("/pawns", pawnController.FindAllBy)

	bidModel := model.NewBids(*s.database)
	bidService := service.NewBid(bidModel)
	bidController := controller.NewBidController(bidService)
	// router.POST("/bids", bidController.InsertOne)
	router.GET("/bids/:id", bidController.FindOne)
	router.GET("/bids", bidController.FindAllBy)
	router.PATCH("/bids/:id", bidController.UpdateOne)

	bidNPawnController := controller.NewBidNPawnController(bidService, pawnService)
	insertBidToPawn := s.connection.GetSession(bidNPawnController.InsertBidToPawn)
	acceptBid := s.connection.GetSession(bidNPawnController.AcceptBid)
	router.POST("/bids-pawns", insertBidToPawn)
	router.PATCH("/bids-pawns/:id", acceptBid)

	router.POST("/auth", userController.CreateLogin(s.tokenMaker))
	s.router = router
}

func (s *Server) Start(address string) error {
	return s.router.Run(address)
}
